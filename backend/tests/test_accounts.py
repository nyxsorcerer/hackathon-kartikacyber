import json

import httpx
import pytest
from sqlalchemy import select

from conftest import FixtureBroker, connection, application, source_snapshot
from numen import domain
from numen.models import Account, Commit, Job, JobAttempt, JobEvent, Application, Transcript
from numen.queue import ExecutionContext, claim
from numen.security import DomainError
from numen.worker import run_once
from numen.workflows import ISSUE_TYPES


@pytest.mark.parametrize("agent", ["pi", "claude"])
def test_anthropic_account_routes_selected_runtime_catalog_and_publishes_report(system, agent):
    app, client, config = system
    account = client.post(
        "/api/accounts",
        json={
            "label": "Anthropic API",
            "provider": "claude",
            "auth_type": "api_key",
            "api_key": "fixture-anthropic-key-no-access",
        },
    ).json()
    catalogs = {
        "pi": [{"id": "pi-model", "name": "Pi model", "reasoning_efforts": ["low", "high"]}],
        "claude": [
            {"id": "claude-model", "name": "Claude model", "reasoning_efforts": ["high", "max"]}
        ],
    }

    def discovery(call):
        return {"models": catalogs[call["profile"]["agent"]], "usage": None}, {}

    caps = client.post(f"/api/accounts/{account['id']}/capabilities").json()["job_id"]
    assert run_once(config, app.state.factory, FixtureBroker(handler=discovery))
    assert client.get(f"/api/jobs/{caps}").json()["status"] == "succeeded"
    public = client.get("/api/accounts").json()["items"][0]
    assert public["supported_agents"] == ["pi", "claude"]
    assert {name: models[0]["id"] for name, models in public["agent_models"].items()} == {
        "pi": "pi-model", "claude": "claude-model"
    }
    monitored = application(client)
    commit_id = source_snapshot(app, monitored["id"])
    endpoint = f"/api/commits/{commit_id}/analyses"
    profile = {
        "agent": agent,
        "connection_id": account["id"],
        "model_id": catalogs[agent][0]["id"],
        "reasoning_effort": catalogs[agent][0]["reasoning_efforts"][-1],
    }
    other = "claude" if agent == "pi" else "pi"
    assert client.post(
        endpoint, json={"profile": {**profile, "model_id": catalogs[other][0]["id"]}}
    ).status_code == 422
    queued = client.post(endpoint, json={"profile": profile}).json()["job_id"]
    result = {
        "verdict": "Insufficient context", "summary": "Fixture source evidence",
        "title": "Input parsing needs more source evidence", "vulnerable_ref": None,
        "evidence": [{"path": "main.py", "lines": [1, 2]}],
        "confidence": "low",
        "open_questions": [], "before_after": "Recorded diff", "affected_behavior": "Parsing",
    }
    broker = FixtureBroker(result, {"report.md": b"# Fixture analysis\nRecorded evidence"})
    assert run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    assert broker.calls[0]["profile"]["agent"] == agent
    assert broker.calls[0]["profile"]["model_id"] == profile["model_id"]
    assert broker.calls[0]["profile"]["reasoning_effort"] == profile["reasoning_effort"]
    analysis = client.get(f"/api/commits/{commit_id}").json()["analyses"][0]
    assert analysis["profile"] == profile
    report = next(a for a in analysis["artifacts"] if a["path"] == "report.md")
    assert client.get(f"/api/artifacts/{report['id']}/content").content == broker.outputs["report.md"]
    assert "fixture-anthropic-key-no-access" not in json.dumps(client.get("/api/jobs").json())


def test_partial_anthropic_capabilities_offer_only_successful_runtime(system):
    app, client, config = system
    account = client.post(
        "/api/accounts",
        json={"label": "API", "provider": "claude", "auth_type": "api_key", "api_key": "fixture-key"},
    ).json()

    class PiOnlyBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            if self.calls[-1]["profile"]["agent"] == "claude":
                raise DomainError("unsupported_access", "Claude fixture access unavailable", 422)
            return super().wait(run_id, heartbeat, progress, deadline)

    queued = client.post(f"/api/accounts/{account['id']}/capabilities").json()["job_id"]
    assert run_once(
        config, app.state.factory,
        PiOnlyBroker({"models": [{"id": "pi-model", "name": "Pi", "reasoning_efforts": []}]}),
    )
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["supported_agents"] == ["pi"]
    assert set(public["agent_models"]) == {"pi"}
    assert public["capability_errors"]["claude"]["code"] == "unsupported_access"


def test_disabled_commandcode_plugin_never_runs_and_enabled_plugin_is_sent(system):
    app, client, config = system
    account = client.post(
        "/api/accounts",
        json={
            "label": "Command Code",
            "provider": "commandcode",
            "auth_type": "api_key",
            "api_key": "fixture-commandcode-key",
        },
    ).json()
    plugin = "/api/plugins/pi-commandcode-provider"
    catalog = {"models": [{"id": "cc/model", "name": "CC", "reasoning_efforts": ["high"]}]}
    assert client.patch(plugin, json={"enabled": False}).json()["enabled"] is False
    for action in ("check", "capabilities"):
        job_id = client.post(f"/api/accounts/{account['id']}/{action}").json()["job_id"]
        broker = FixtureBroker(catalog)
        assert run_once(config, app.state.factory, broker)
        job = client.get(f"/api/jobs/{job_id}").json()
        assert job["status"] == "failed" and job["error"]["code"] == "plugin_unavailable"
        assert broker.calls == []
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "unavailable" and public["supported_agents"] == []

    client.patch(plugin, json={"enabled": True})
    job_id = client.post(f"/api/accounts/{account['id']}/capabilities").json()["job_id"]
    broker = FixtureBroker(catalog)
    assert run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    assert [call["profile"]["enabled_plugins"] for call in broker.calls] == [
        ["pi-commandcode-provider"]
    ]
    assert client.get("/api/accounts").json()["items"][0]["supported_agents"] == ["pi"]

    monitored = application(client)
    commit_id = source_snapshot(app, monitored["id"])
    profile = {
        "agent": "pi",
        "connection_id": account["id"],
        "model_id": "cc/model",
        "reasoning_effort": "high",
    }
    endpoint = f"/api/commits/{commit_id}/analyses"
    queued = client.post(endpoint, json={"profile": profile}).json()["job_id"]
    # Disabling applies to jobs that were queued before the change.
    client.patch(plugin, json={"enabled": False})
    assert client.post(endpoint, json={"profile": profile}).status_code == 422
    broker = FixtureBroker()
    assert run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "plugin_unavailable"
    assert broker.calls == []


def test_native_login_reuses_pending_attempt_until_it_is_stopped(system):
    _, client, _ = system
    account = client.post(
        "/api/accounts",
        json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"},
    ).json()
    endpoint = f"/api/accounts/{account['id']}/login"
    first = client.post(endpoint).json()["job_id"]
    assert client.post(endpoint).json()["job_id"] == first
    assert client.post(f"/api/jobs/{first}/cancel").status_code == 202
    assert client.get(f"/api/jobs/{first}").json()["status"] == "cancelled"
    assert client.post(endpoint).json()["job_id"] != first


def test_native_login_instructions_visible_while_runtime_progress_is_unchanged(system):
    app, client, _ = system
    account = client.post(
        "/api/accounts",
        json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"},
    ).json()
    job_id = client.post(f"/api/accounts/{account['id']}/login").json()["job_id"]
    with app.state.factory.begin() as db:
        job = claim(db, "login-test")
        assert job.id == job_id
    context = ExecutionContext(app.state.factory, job, FixtureBroker())
    state = {
        "status": "running",
        "progress": 5,
        "events": [{"type": "workload_started"}],
    }
    context.progress(state)
    state["events"].append(
        {
            "type": "login_instruction",
            "message": "https://auth.openai.com/codex/device",
        }
    )
    context.progress(state)
    response = client.get(f"/api/accounts/{account['id']}/login")
    assert response.json()["status"] == "running"
    assert any(
        event.get("verification_uri") == "https://auth.openai.com/codex/device"
        for event in response.json()["events"]
    )
    state["events"].extend(
        [
            {"type": "login_instruction", "message": "ABCD-12345"},
            {"type": "login_instruction", "message": "private-token-fixture"},
        ]
    )
    context.progress(state)
    context.progress(state)
    response = client.get(f"/api/accounts/{account['id']}/login")
    assert sum(event.get("user_code") == "ABCD-12345" for event in response.json()["events"]) == 1
    assert "private-token-fixture" not in response.text
    with app.state.factory() as db:
        events = list(db.scalars(select(JobEvent).where(JobEvent.job_id == job_id)))
        assert sum(event.data.get("kind") == "login" for event in events) == 2


def test_native_login_ingests_secret_before_cleanup_and_refreshes_capabilities(system):
    app, client, config = system
    account = client.post(
        "/api/accounts",
        json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"},
    ).json()
    job_id = client.post(f"/api/accounts/{account['id']}/login").json()["job_id"]
    cache = {"auth_json": {"tokens": {"access_token": "fixture-login-private-token"}}}

    class NativeBroker(FixtureBroker):
        def credential(self, run_id):
            return cache

        def delete_credential(self, run_id):
            with app.state.factory() as db:
                row = db.get(Account, account["id"])
                assert app.state.vault.decrypt(row.credential) == cache
            super().delete_credential(run_id)

    broker = NativeBroker(
        {
            "status": "ready",
            "models": [{"id": "native-model", "name": "Native", "reasoning_efforts": []}],
            "usage": None,
        }
    )
    assert run_once(config, app.state.factory, broker)
    response = client.get(f"/api/jobs/{job_id}")
    assert response.json()["status"] == "succeeded"
    assert response.json()["result"]["status"] == "signed_in"
    assert broker.ingress_deleted
    with app.state.factory() as db:
        row = db.get(Account, account["id"])
        assert row.revision == 2 and "fixture-login-private-token" not in row.credential
        followups = list(db.scalars(select(Job).where(Job.status == "queued")))
        assert {job.kind for job in followups} == {"credential_cleanup", "account_capabilities"}
    assert run_once(config, app.state.factory, broker)
    assert run_once(config, app.state.factory, broker)
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["credential_configured"]
    assert public["agent_models"]["codex"][0]["id"] == "native-model"
    assert "fixture-login-private-token" not in json.dumps(client.get("/api/jobs").json())


def claude_native(client):
    return client.post(
        "/api/accounts",
        json={"label": "Claude", "provider": "claude", "auth_type": "native_oauth"},
    ).json()


def test_claude_login_code_requires_a_waiting_claude_login(system):
    app, client, _ = system
    account = claude_native(client)
    endpoint = f"/api/accounts/{account['id']}/login/code"
    code = {"code": "fixture-authorization-code#fixture-state"}
    assert client.post(endpoint, json=code).json()["code"] == "login_not_waiting"
    client.post(f"/api/accounts/{account['id']}/login")
    with app.state.factory.begin() as db:
        job = claim(db, "login-test")
    assert client.post(endpoint, json=code).status_code == 409
    ExecutionContext(app.state.factory, job, FixtureBroker()).progress(
        {
            "status": "running",
            "events": [
                {
                    "type": "login_instruction",
                    "verification_uri": "https://claude.com/cai/oauth/authorize?code=true",
                    "input_required": "authorization_code",
                }
            ],
        }
    )
    assert client.post(endpoint, json={"code": "bad code\nwith newline"}).status_code == 422
    assert client.post(endpoint, json={"code": "short"}).status_code == 422
    accepted = client.post(endpoint, json={"code": "  " + code["code"] + "\n"})
    assert accepted.status_code == 202 and accepted.json()["job_id"] == job.id
    with app.state.factory() as db:
        sealed = db.get(JobAttempt, job.attempt_token).data["login_code"]
        assert code["code"] not in sealed
        assert app.state.vault.decrypt(sealed) == code
    events = client.get(f"/api/accounts/{account['id']}/login").json()["events"]
    assert any(e.get("input_required") == "authorization_code" for e in events)
    assert any(e.get("status") == "code_received" for e in events)
    assert code["code"] not in json.dumps(client.get(f"/api/jobs/{job.id}").json())
    codex = client.post(
        "/api/accounts",
        json={"label": "Codex", "provider": "openai", "auth_type": "native_oauth"},
    ).json()
    assert client.post(f"/api/accounts/{codex['id']}/login/code", json=code).status_code == 422


def test_claude_login_relays_code_once_and_ingests_native_cache(system):
    app, client, config = system
    account = claude_native(client)
    job_id = client.post(f"/api/accounts/{account['id']}/login").json()["job_id"]
    code = "fixture-authorization-code#fixture-state"
    cache = {"credentials_json": {"claudeAiOauth": {"accessToken": "fixture-claude-login-token"}}}

    class ClaudeLoginBroker(FixtureBroker):
        relayed = []

        def wait(self, run_id, heartbeat, progress, deadline=900):
            heartbeat()
            running = {
                "run_id": run_id,
                "status": "running",
                "events": [
                    {
                        "type": "login_instruction",
                        "verification_uri": "https://claude.com/cai/oauth/authorize?code=true",
                        "input_required": "authorization_code",
                    }
                ],
            }
            progress(running)
            assert self.relayed == []
            submitted = client.post(f"/api/accounts/{account['id']}/login/code", json={"code": code})
            assert submitted.status_code == 202
            progress(running)
            progress(running)
            return self.states[run_id]

        def login_input(self, run_id, value):
            self.relayed.append((run_id, value))

        def credential(self, run_id):
            return cache

    broker = ClaudeLoginBroker({"status": "ready", "auth_type": "native_oauth"})
    assert run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "succeeded" and job["result"]["status"] == "signed_in"
    assert broker.calls[0]["profile"]["agent"] == "claude"
    assert [value for _, value in broker.relayed] == [code]
    with app.state.factory() as db:
        row = db.get(Account, account["id"])
        assert app.state.vault.decrypt(row.credential) == cache
        attempt = db.scalar(select(JobAttempt).where(JobAttempt.job_id == job_id))
        assert "login_code" not in attempt.data
    assert code not in json.dumps(client.get("/api/jobs").json())
    assert "fixture-claude-login-token" not in json.dumps(client.get("/api/jobs").json())


def test_claude_login_code_delivery_failure_asks_for_resubmission(system):
    app, client, config = system
    account = claude_native(client)
    client.post(f"/api/accounts/{account['id']}/login")
    with app.state.factory.begin() as db:
        job = claim(db, "login-test")
    context = ExecutionContext(app.state.factory, job, FixtureBroker())
    running = {
        "run_id": "run",
        "status": "running",
        "events": [{"type": "login_instruction", "input_required": "authorization_code"}],
    }
    context.progress(running)
    client.post(
        f"/api/accounts/{account['id']}/login/code",
        json={"code": "fixture-authorization-code#fixture-state"},
    )

    class UnavailableBroker(FixtureBroker):
        def login_input(self, run_id, value):
            raise DomainError("broker_error", "Execution broker returned HTTP 409", 502)

    from numen.workflows import Workflows

    workflows = Workflows(config, app.state.vault, UnavailableBroker(), context)
    try:
        workflows.relay_login_code(job.id, "run")
    finally:
        workflows.close()
    events = client.get(f"/api/accounts/{account['id']}/login").json()["events"]
    assert events[-1]["status"] == "code_delivery_failed"
    assert workflows.take_login_code() is None


@pytest.mark.parametrize(
    "provider,cache,wrapper,agent",
    [
        (
            "openai",
            {
                "tokens": {
                    "access_token": "native-openai-access-fixture",
                    "refresh_token": "native-openai-refresh-fixture",
                    "id_token": "native-openai-id-fixture",
                },
                "last_refresh": "2026-10-04T00:00:00Z",
            },
            "auth_json",
            "codex",
        ),
        (
            "claude",
            {
                "claudeAiOauth": {
                    "accessToken": "native-claude-access-fixture",
                    "refreshToken": "native-claude-refresh-fixture",
                    "expiresAt": 2000000000000,
                    "scopes": ["user:inference"],
                }
            },
            "credentials_json",
            "claude",
        ),
    ],
)
def test_native_cache_file_import_encrypted_redacted_and_capabilities(
    system, provider, cache, wrapper, agent
):
    app, client, config = system
    account = client.post(
        "/api/accounts", json={"label": "Native", "provider": provider, "auth_type": "native_oauth"}
    ).json()
    response = client.post(
        f"/api/accounts/{account['id']}/native-cache",
        files={"file": ("credentials.json", json.dumps(cache), "application/json")},
    )
    assert response.status_code == 200
    public = response.json()
    assert public["credential_configured"] and public["status"] == "unchecked"
    assert "accessToken" not in response.text and "refresh_token" not in response.text
    with app.state.factory() as db:
        row = db.get(Account, account["id"])
        assert row.revision == 2 and app.state.vault.decrypt(row.credential) == {wrapper: cache}
        assert "fixture" not in row.credential
    queued = client.post(f"/api/accounts/{account['id']}/capabilities").json()["job_id"]
    broker = FixtureBroker(
        {
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
    )
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["supported_agents"] == [agent]
    assert broker.calls[0]["profile"]["credential"] == {wrapper: cache}


def commandcode_native(client):
    return client.post(
        "/api/accounts",
        json={"label": "Command Code", "provider": "commandcode", "auth_type": "native_oauth"},
    ).json()


def test_commandcode_login_runs_pi_plugin_flow_and_relays_pasted_key(system):
    app, client, config = system
    account = commandcode_native(client)
    assert account["supported_agents"] == ["pi"]
    job_id = client.post(f"/api/accounts/{account['id']}/login").json()["job_id"]
    key = "user_fixture-commandcode-login-key"
    entry = {"type": "oauth", "access": key, "refresh": key, "expires": 2106459876554}

    class CommandCodeLoginBroker(FixtureBroker):
        relayed = []

        def wait(self, run_id, heartbeat, progress, deadline=900):
            heartbeat()
            running = {
                "run_id": run_id,
                "status": "running",
                "events": [
                    {
                        "type": "login_instruction",
                        "verification_uri": "https://commandcode.ai/studio/auth/cli?state=x",
                        "input_required": "api_key",
                    }
                ],
            }
            progress(running)
            submitted = client.post(f"/api/accounts/{account['id']}/login/code", json={"code": key})
            assert submitted.status_code == 202
            progress(running)
            return self.states[run_id]

        def login_input(self, run_id, value):
            self.relayed.append(value)

        def credential(self, run_id):
            return {"auth_json": {"commandcode": entry}}

    broker = CommandCodeLoginBroker({"status": "ready", "auth_type": "native_oauth"})
    assert run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    login = broker.calls[0]["profile"]
    assert login["agent"] == "pi" and login["enabled_plugins"] == ["pi-commandcode-provider"]
    assert broker.relayed == [key]
    catalog = {"models": [{"id": "cc/model", "name": "CC", "reasoning_efforts": ["high"]}]}
    capabilities = FixtureBroker(catalog)
    assert run_once(config, app.state.factory, capabilities)  # credential cleanup
    assert run_once(config, app.state.factory, capabilities)  # capability refresh
    refresh = capabilities.calls[0]["profile"]
    assert refresh["agent"] == "pi" and refresh["auth_type"] == "native_oauth"
    assert refresh["credential"] == {"auth_json": {"commandcode": entry}}
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["supported_agents"] == ["pi"]
    assert key not in json.dumps(client.get("/api/jobs").json())


def test_commandcode_login_requires_enabled_plugin(system):
    _, client, _ = system
    account = commandcode_native(client)
    client.patch("/api/plugins/pi-commandcode-provider", json={"enabled": False})
    response = client.post(f"/api/accounts/{account['id']}/login")
    assert response.status_code == 422 and response.json()["code"] == "plugin_unavailable"


@pytest.mark.parametrize(
    "cache",
    [
        {"commandcode": {"type": "oauth", "access": "user_fixture-import-key",
                         "refresh": "user_fixture-import-key", "expires": 2106459876554}},
        {"auth_json": {"commandcode": {"type": "api_key", "key": "user_fixture-import-key"}}},
        {"apiKey": "user_fixture-import-key", "userName": "fixture"},
    ],
)
def test_commandcode_native_import_accepts_pi_and_cli_auth_files(system, cache):
    app, client, _ = system
    account = commandcode_native(client)
    endpoint = f"/api/accounts/{account['id']}/native-cache"
    response = client.post(endpoint, files={"file": ("auth.json", json.dumps(cache))})
    assert response.status_code == 200 and "user_fixture-import-key" not in response.text
    with app.state.factory() as db:
        stored = app.state.vault.decrypt(db.get(Account, account["id"]).credential)
    key = "user_fixture-import-key"
    assert stored == {"auth_json": {"commandcode": {"type": "oauth", "access": key, "refresh": key}}}
    from numen.workflows import credential_strings

    assert key in credential_strings(stored)
    rejected = client.post(endpoint, files={"file": ("auth.json", json.dumps({"openai": {}}))})
    assert rejected.status_code == 422


def test_native_cache_mode_json_shape_and_size_rejected_without_echo(system):
    _, client, _ = system
    api = client.post(
        "/api/accounts", json={"label": "API", "provider": "openai", "auth_type": "api_key"}
    ).json()
    assert (
        client.post(
            f"/api/accounts/{api['id']}/native-cache", files={"file": ("cache.json", b"{}")}
        ).status_code
        == 422
    )
    native = client.post(
        "/api/accounts", json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"}
    ).json()
    endpoint = f"/api/accounts/{native['id']}/native-cache"
    assert client.post(endpoint, files={"file": ("cache.json", b"not json")}).status_code == 422
    invalid = {
        "OPENAI_API_KEY": "must-not-be-echoed-fixture",
        "tokens": {"access_token": "dummy", "refresh_token": "dummy"},
    }
    response = client.post(endpoint, files={"file": ("cache.json", json.dumps(invalid))})
    assert response.status_code == 422 and "must-not-be-echoed-fixture" not in response.text
    assert (
        client.post(endpoint, files={"file": ("cache.json", b"x" * (1024 * 1024 + 1))}).status_code
        == 413
    )
    too_large = {
        "tokens": {"access_token": "a", "refresh_token": "b"},
        "padding": "x" * (256 * 1024),
    }
    assert (
        client.post(endpoint, files={"file": ("cache.json", json.dumps(too_large))}).status_code
        == 413
    )
    assert not client.get("/api/accounts").json()["items"][1]["credential_configured"]


@pytest.mark.parametrize("complete,choice,kind,expected", [
    (False, "unrelated", "unrelated", "pending"),
    (True, "unrelated", "unrelated", "dismissed"),
    (True, "security_candidate", "vulnerability_introduction", "candidate"),
])
def test_jev_official_model_discovery_and_typed_triage_keeps_uncertainty(system, monkeypatch, complete, choice, kind, expected):
    app, client, config = system
    account = client.post(
        "/api/accounts",
        json={
            "label": "Jev",
            "provider": "jev",
            "auth_type": "api_key",
            "api_key": "jev-fixture-key-not-real",
        },
    ).json()
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, **kwargs: httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.typesafe.ai/v1/models"),
            json={
                "models": [
                    {
                        "name": "jev-latest",
                        "description": "Stable alias",
                        "release_date": "2026-10-01",
                    }
                ]
            },
        ),
    )
    client.post(f"/api/accounts/{account['id']}/check")
    run_once(config, app.state.factory, FixtureBroker())
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["models"][0]["id"] == "jev-latest"
    p = application(
        client,
        config={
            "triage_mode": "jev",
            "jev_connection_id": account["id"],
            "jev_model_id": "jev-latest",
        },
    )
    commit_id = source_snapshot(app, p["id"])
    with app.state.factory.begin() as db:
        commit = db.get(Commit, commit_id)
        commit.data = {**commit.data, "diff_complete": complete}
        monitored = db.get(Application, p["id"])
        job = domain.enqueue(
            db,
            "jev_triage",
            monitored,
            domain.job_input(
                db, monitored, commit_id=commit.id, **domain.resolve_jev(db, monitored.config)
            ),
        )
        job_id = job.id
    calls = []

    def typed_post(url, json, **kwargs):
        calls.append((url, json))
        assert "state" in json and json["model"] == "jev-latest"
        assert json["questions"]["commit_security"]["type"] == "choice"
        return httpx.Response(
            200,
            json={
                "model": "jev-1.13.0",
                "answers": {
                    "commit_security": {
                        "type": "choice",
                        "choice": choice,
                        "confidence": 0.8,
                        "probabilities": {
                            "security_candidate": 0.8 if choice == "security_candidate" else 0.1,
                            "unrelated": 0.8 if choice == "unrelated" else 0.1,
                            "insufficient_context": 0.1,
                        },
                    },
                    "change_kind": {"type": "choice", "choice": kind, "confidence": 0.8, "probabilities": {name: 0.8 if name == kind else 0.05 for name in ("vulnerability_fix", "security_hardening", "vulnerability_introduction", "unrelated", "insufficient_context")}},
                    "issue_type": {"type": "choice", "choice": "other", "confidence": 0.9, "probabilities": {kind: float(kind == "other") for kind in ISSUE_TYPES}},
                },
                "usage": {"input_tokens": 100, "output_tokens": 10},
            },
        )

    monkeypatch.setattr(httpx, "post", typed_post)
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    result = client.get(f"/api/commits/{commit_id}").json()["triage_result"]
    assert result["decision"] == (choice if complete else "insufficient_context")
    assert client.get(f"/api/commits/{commit_id}").json()["review_decision"] == expected
    assert result["title"]
    assert result["change_kind"] == (kind if complete else "insufficient_context")
    assert result["model_id"] == "jev-1.13.0" and result["selected_model_id"] == "jev-latest"
    assert result["probabilities"][choice] == 0.8
    assert calls[0][0] == "https://api.typesafe.ai/v1/systemone"
    assert "jev-fixture-key-not-real" not in json.dumps(client.get("/api/jobs").json())
    # The Jev request and its typed answer are kept as the run's Transcript, without the key.
    with app.state.factory() as db:
        (transcript,) = db.scalars(select(Transcript).where(Transcript.job_id == job_id))
    assert (transcript.kind, transcript.subject_id, transcript.data["status"]) == ("triage", commit_id, "completed")
    assert transcript.data["request"] == calls[0][1]
    assert json.loads(transcript.data["response"])["model"] == "jev-1.13.0"
    assert "jev-fixture-key-not-real" not in json.dumps(transcript.data)


def test_runtime_events_reach_the_timeline_with_application_owned_messages(system):
    app, client, config = system
    connection(app)
    p = application(client)
    job_id = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    with app.state.factory.begin() as db:
        job = claim(db, "runtime-event-test")
        assert job.id == job_id
    context = ExecutionContext(app.state.factory, job, FixtureBroker())
    forged = "credential-fixture-must-not-appear"
    state = {
        "status": "running",
        "progress": 1,
        "run_id": "run-a",
        "events": [
            {"type": "lab_build", "message": forged},
            {"type": "lab_application_exited", "message": forged, "image": forged},
            {"type": "agent_chatter", "message": "unknown kinds are dropped"},
            # The build daemon is gone, so its former milestones are unknown kinds too.
            {"type": "build_daemon_started", "message": forged},
            {"type": "repository_ready", "message": forged},
        ],
    }
    context.progress(state)
    context.progress(state)  # Repeated polling must not duplicate a milestone.
    events = client.get(f"/api/jobs/{job_id}/events").json()["items"]
    kinds = [event["kind"] for event in events]
    assert kinds.count("lab_build") == 1 and kinds.count("lab_application_exited") == 1
    assert not {"agent_chatter", "build_daemon_started", "repository_ready"} & set(kinds)
    assert forged not in client.get(f"/api/jobs/{job_id}/events").text
    assert any(
        event["kind"] == "lab_application_exited"
        and event["message"] == "The pinned application stopped before it could be verified"
        and "image" not in event
        for event in events
    )
    # A later runtime phase reports its own milestones rather than being suppressed by the first.
    context.progress({**state, "run_id": "run-b", "progress": 2})
    again = client.get(f"/api/jobs/{job_id}/events").json()["items"]
    assert [e["kind"] for e in again].count("lab_build") == 2
    assert client.get("/api/dashboard").text.count("lab_build") == 0
