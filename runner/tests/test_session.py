import json

import pytest
from fastapi.testclient import TestClient

from numen_runner import session
from numen_runner.adapters import agent_argv
from numen_runner.broker import create_app

SCHEMA = {"type": "object", "required": ["category"], "properties": {"category": {"type": "string"}}}


def test_interactive_argv_drops_print_mode_and_keeps_policy(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    claude = session.agent_argv(agent_argv({"agent": "claude", "model_id": "m", "auth_type": "api_key", "operation": "commit_triage"},
                                           str(schema), session=True), "claude")
    assert not {"--print", "--output-format", "--json-schema", "--no-session-persistence"} & set(claude)
    assert '{"type":"object"}' not in claude
    assert claude[claude.index("--tools") + 1] == "Read,Grep,Glob,Write,Edit"  # writes its result file
    assert {"--permission-mode", "--restricted", "--strict-mcp-config", "--bare"} <= set(claude)
    codex = session.agent_argv(agent_argv({"agent": "codex", "model_id": "m", "operation": "commit_triage"}, session=True), "codex")
    assert not {"exec", "--json", "--output-schema", "--output-last-message", "-", "never"} & set(codex)
    assert 'permissions.numen.extends=":workspace"' in codex and 'approval_policy="never"' in codex
    pi = session.agent_argv(agent_argv({"agent": "pi", "model_id": "m", "provider_id": "deepseek", "operation": "cve_analysis"}), "pi")
    assert "--print" not in pi and "--mode" not in pi and "json" not in pi
    assert pi[-3:] == ["--tui-mode", "regular", "--offline"] and "--no-builtin-tools" in pi


class FakeHerdr:
    """Scripted agent states and screens; records prompts the session sends."""

    def __init__(self, states, on_poll=None):
        self.states, self.on_poll, self.prompts, self.polls = list(states), on_poll, [], 0

    def __call__(self, method, **params):
        if method == "agent.get":
            self.polls += 1
            if self.on_poll:
                self.on_poll(self.polls)
            return {"agent": {"agent_status": self.states.pop(0) if self.states else "idle"}}
        if method == "pane.read":
            return {"read": {"text": "screen"}}
        if method == "agent.prompt":
            self.prompts.append(params["text"])
            return {}
        raise AssertionError(method)


@pytest.fixture
def paths(tmp_path, monkeypatch):
    (tmp_path / "outputs").mkdir()
    monkeypatch.setattr(session, "RESULT", tmp_path / "outputs" / "result.json")
    monkeypatch.setattr(session, "HOLD", tmp_path / "hold")
    return tmp_path


def test_session_returns_valid_result_once_agent_is_quiet(paths, monkeypatch):
    def write(poll):
        if poll == 2:
            session.RESULT.write_text(json.dumps({"category": "Security fix"}))
    herdr = FakeHerdr(["working", "working"], write)
    monkeypatch.setattr(session, "call", herdr)
    assert session.watch(SCHEMA, "w1:p1", sleep=lambda _: None) == {"category": "Security fix"}
    assert not session.RESULT.exists() and not herdr.prompts


def test_session_reminds_with_validation_error_then_gives_up(paths, monkeypatch):
    session.RESULT.write_text(json.dumps({"wrong": True}))
    herdr = FakeHerdr([])
    monkeypatch.setattr(session, "call", herdr)
    with pytest.raises(ValueError, match="without a valid result"):
        session.watch(SCHEMA, "w1:p1", sleep=lambda _: None)
    assert len(herdr.prompts) == session.NUDGES and "'category' is a required property" in herdr.prompts[0]


def test_held_session_does_not_finish_until_released(paths, monkeypatch):
    session.RESULT.write_text(json.dumps({"category": "Security fix"}))
    session.HOLD.touch()
    herdr = FakeHerdr([], lambda poll: poll == 20 and session.HOLD.unlink())
    monkeypatch.setattr(session, "call", herdr)
    assert session.watch(SCHEMA, "w1:p1", sleep=lambda _: None)["category"] == "Security fix"
    assert herdr.polls == 20  # finishes on the first check after release


class SessionEngine:
    def __init__(self):
        self.sent = []

    def ping(self):
        raise RuntimeError("offline")

    def cleanup(self, run_id):
        pass

    def session(self, run_id, *args):
        if args[0] == "read":
            return {"agent": "claude", "agent_status": "idle", "screen": "key sk-live-secret-value shown", "held": False}
        self.sent.append(json.loads(args[1]))
        return {}


def test_broker_session_redacts_credentials_and_validates_input(tmp_path):
    engine = SessionEngine()
    app = create_app("test-token", tmp_path, engine=engine, execute=False)
    headers = {"X-Broker-Token": "test-token"}
    with TestClient(app) as client:
        run = client.post("/internal/runs", headers=headers, json={"attempt_token": "s", "kind": "probe"}).json()["run_id"]
        assert client.get(f"/internal/runs/{run}/session", headers=headers).status_code == 409  # queued, no session
        app.state.store.change(run, status="running")
        app.state.store.session_secrets[run] = ["sk-live-secret-value"]
        state = client.get(f"/internal/runs/{run}/session", headers=headers).json()
        assert "sk-live-secret-value" not in state["screen"] and "[redacted]" in state["screen"]
        url = f"/internal/runs/{run}/session"
        assert client.post(url, headers=headers, json={"action": "prompt"}).status_code == 422
        assert client.post(url, headers=headers, json={"action": "keys", "keys": ["$(rm -rf)"]}).status_code == 422
        assert client.post(url, headers=headers, json={"action": "prompt", "text": "explain step 2"}).status_code == 202
        assert client.post(url, headers=headers, json={"action": "keys", "keys": ["esc"]}).status_code == 202
        assert engine.sent == [{"action": "prompt", "text": "explain step 2"}, {"action": "keys", "keys": ["esc"]}]


def test_start_waits_for_herdr_readiness_and_prompt_retries_until_ready(monkeypatch):
    # agent.start may return before the agent is ready; Pi then rejects prompts with agent_not_ready.
    log = {"gets": 0, "prompts": 0}

    def herdr(method, **params):
        if method == "ping":
            return {}
        if method == "workspace.create":
            return {"root_pane": {"pane_id": "w1:p1"}}
        if method == "agent.start":
            return {}
        if method == "agent.get":
            log["gets"] += 1
            return {"agent": {"interactive_ready": True if log["gets"] > 5 else None}}
        if method == "pane.read":
            return {"read": {"text": "$ pi --long command\nline\nline\nline\nline"}}
        if method == "agent.prompt":
            log["prompts"] += 1
            if log["prompts"] < 3:
                raise session.HerdrError("agent.prompt agent_not_ready")
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(session, "call", herdr)
    monkeypatch.setattr(session.time, "sleep", lambda _: None)
    server = type("Server", (), {"poll": lambda self: None})()
    assert session.start(["pi", "--print", "--mode", "json"], {"agent": "pi"}, server) == "w1:p1"
    assert log["gets"] >= 5 + session.SETTLED  # never settles before herdr reports readiness
    session.submit("task", session.time.monotonic() + 60)
    assert log["prompts"] == 3
    with pytest.raises(session.HerdrError):
        monkeypatch.setitem(log, "prompts", 0)
        session.submit("task", session.time.monotonic() - 1)  # deadline passed: not_ready surfaces
