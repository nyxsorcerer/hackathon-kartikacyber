import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from numen.api import create_app
from numen.config import Config
from numen.models import Account, Commit, Program, Setting, Snapshot
from numen.artifacts import publish


@pytest.fixture
def system(tmp_path):
    config = Config(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "artifacts",
        secret_key=Fernet.generate_key().decode(),
        test_mode=True,
        frontend_root=Path("/missing-frontend"),
        monitor_interval_days=2,
    )
    app = create_app(config=config, admin_password="test-password-long")
    with TestClient(app) as client:
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-long"}
        ).json()
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        yield app, client, config


def program(client, **overrides):
    body = {
        "asset_name": "Site",
        "asset_url": "https://example.com",
        "product_kind": "plugin",
        "product_name": "Demo",
        "source_kind": "github",
        "source_url": "https://github.com/demo/plugin",
        "source_ref": "main",
        "monitor_interval_days": 2,
    }
    result = client.post("/api/programs", json={**body, **overrides})
    assert result.status_code == 201, result.text
    return result.json()


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
            "agent": "codex",
            "connection_id": account.id,
            "model_id": "test-model",
            "reasoning_effort": "high",
        }
        setting = db.get(Setting, "global")
        setting.data = {
            **setting.data,
            "default_profiles": {
                op: profile
                for op in (
                    "commit_analysis",
                    "commit_triage",
                    "version_recipe",
                    "audit_context",
                    "cve_analysis",
                    "finding_artifacts",
                )
            },
        }
    return profile


def source_snapshot(app, ident, revision="a" * 40):
    with app.state.factory.begin() as db:
        row = db.get(Program, ident)
        row.cursor = revision
        source = Snapshot(
            program_id=ident,
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
            program_id=ident,
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
