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
    claude = session.agent_argv(agent_argv({"agent": "claude", "model_id": "m", "auth_type": "api_key", "operation": "commit_analysis"},
                                           str(schema)), "claude")
    assert not {"--print", "--output-format", "--json-schema", "--no-session-persistence", "--allowedTools"} & set(claude)
    assert '{"type":"object"}' not in claude
    assert claude[claude.index("--tools") + 1] == "Read,Grep,Glob,Write,Edit"  # writes its result file
    # The session keeps the print run's permission rules: writes are approved under outputs/ only.
    assert json.loads(claude[claude.index("--settings") + 1]) == {"permissions": {"allow": ["Edit(//workspace/outputs/**)"]}}
    assert {"--permission-mode", "--restricted", "--strict-mcp-config"} <= set(claude) and "--bare" not in claude
    codex = session.agent_argv(agent_argv({"agent": "codex", "model_id": "m", "operation": "audit_context"}), "codex")
    assert not {"exec", "--json", "--output-schema", "--output-last-message", "-", "never"} & set(codex)
    assert 'permissions.numen.extends=":workspace"' in codex and 'approval_policy="never"' in codex
    pi = session.agent_argv(agent_argv({"agent": "pi", "model_id": "m", "provider_id": "deepseek", "operation": "cve_analysis"}), "pi")
    assert "--print" not in pi and "--mode" not in pi and "json" not in pi
    assert "--no-session" not in pi
    assert pi[pi.index("--session-dir") + 1] == "/home/job/session-transcripts/pi"
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


def test_session_keeps_terminal_colors_and_settles_on_text(paths, monkeypatch):
    # A pulsing spinner changes only its color; the screen still counts as settled.
    saved = []

    class Colored(FakeHerdr):
        def __call__(self, method, **params):
            if method == "pane.read":
                assert params["format"] == "ansi"
                return {"read": {"text": f"\x1b[{31 + self.polls % 2}m●\x1b[0m done"}}
            return super().__call__(method, **params)

    session.RESULT.write_text(json.dumps({"category": "Security fix"}))
    monkeypatch.setattr(session, "call", Colored([]))
    monkeypatch.setattr(session, "save_state", lambda agent, screen, *rest: saved.append(screen))
    monkeypatch.setattr(session, "save_scrollback", lambda scrollback: None)
    assert session.watch(SCHEMA, "w1:p1", sleep=lambda _: None, agent="pi")["category"] == "Security fix"
    assert saved[0] == "\x1b[32m●\x1b[0m done" and saved[1] == "\x1b[31m●\x1b[0m done"
    assert len(saved) == session.SETTLED + 1


def test_broker_redacts_credentials_split_by_terminal_styling(tmp_path):
    engine = SessionEngine()
    engine.session = lambda run_id, *args: {
        "agent": "pi", "agent_status": "idle", "held": False,
        "screen": "key sk-live-\x1b[1m\x1b[38;5;46msecret\x1b[0m-\n value shown",
    }
    app = create_app("test-token", tmp_path, engine=engine, execute=False)
    headers = {"X-Broker-Token": "test-token"}
    with TestClient(app) as client:
        run = client.post("/internal/runs", headers=headers, json={"attempt_token": "s", "kind": "probe"}).json()["run_id"]
        app.state.store.change(run, status="running")
        app.state.store.session_secrets[run] = ["sk-live-secret-value"]
        state = client.get(f"/internal/runs/{run}/session", headers=headers).json()
        assert state["screen"] == "key [redacted] shown"


class ScrollingPane:
    """A terminal whose screen shows the last `rows` lines and whose reads return at most `recent`."""

    def __init__(self, rows, recent):
        self.rows, self.recent, self.output = rows, recent, []

    def __call__(self, method, **params):
        assert method == "pane.read" and params["format"] == "ansi"
        lines = self.output[-self.rows:] if params["source"] == "visible" else self.output[-min(params["lines"], self.recent):]
        return {"read": {"text": "".join(f"\x1b[32m{line}\x1b[0m\r\n" for line in lines)}}


def test_terminal_keeps_scrollback_beyond_one_read_and_marks_gaps(monkeypatch):
    pane = ScrollingPane(rows=4, recent=8)
    monkeypatch.setattr(session, "call", pane)
    monkeypatch.setattr(session, "RECENT", 8)
    scrollback = {"trimmed": 0, "lines": []}
    for poll in range(12):  # 3 new lines per poll: more history than any single read
        pane.output += [f"line {poll * 3 + i}" for i in range(3)]
        scrollback, terminal, screen = session.read_terminal("w1:p1", scrollback)
    assert session.STYLE.sub("", terminal).split("\n") == pane.output
    assert screen == "\n".join(pane.output[-4:])
    pane.output += [f"burst {i}" for i in range(20)]  # more than one read holds between polls
    scrollback, terminal, _ = session.read_terminal("w1:p1", scrollback)
    shown = session.STYLE.sub("", terminal).split("\n")
    # The 32 lines already saved stay; what scrolled past unread is marked, not invented.
    assert shown[:32] == pane.output[:32] and shown[32].startswith("… more output scrolled past")
    assert shown[33:] == pane.output[-8:]


def test_terminal_scrollback_drops_its_oldest_lines_in_batches(monkeypatch):
    pane = ScrollingPane(rows=2, recent=6)
    monkeypatch.setattr(session, "call", pane)
    monkeypatch.setattr(session, "RECENT", 6)
    monkeypatch.setattr(session, "SCROLLBACK", 10)
    monkeypatch.setattr(session, "TRIM", 4)
    scrollback = {"trimmed": 0, "lines": []}
    for poll in range(5):
        pane.output += [f"line {poll * 3 + i}" for i in range(3)]
        scrollback, terminal, _ = session.read_terminal("w1:p1", scrollback)
    assert scrollback["trimmed"] == 7 and len(scrollback["lines"]) == 6
    shown = session.STYLE.sub("", terminal).split("\n")
    assert shown[0].startswith("… 7 earlier lines are not kept here") and shown[1:] == pane.output[7:]


def test_saved_scrollback_must_be_a_regular_file_of_lines(tmp_path):
    from numen_runner.session_history import read_scrollback, save_scrollback
    assert read_scrollback(tmp_path) == {"trimmed": 0, "lines": []}
    save_scrollback({"trimmed": 2, "lines": ["a", "b"]}, tmp_path)
    assert read_scrollback(tmp_path) == {"trimmed": 2, "lines": ["a", "b"]}
    (tmp_path / ".numen-scrollback.json").write_text('{"lines": [1]}')
    with pytest.raises(ValueError):
        read_scrollback(tmp_path)
    (tmp_path / ".numen-scrollback.json").unlink()
    (tmp_path / "secret").write_text('{"lines": ["token"]}')
    (tmp_path / ".numen-scrollback.json").symlink_to(tmp_path / "secret")
    with pytest.raises(ValueError):
        read_scrollback(tmp_path)


@pytest.mark.parametrize("agent", ["claude", "pi"])
def test_claude_session_keeps_its_conversation_in_terminal_scrollback(agent, monkeypatch, tmp_path):
    # Claude's default fullscreen renderer uses the alternate screen, which has no scrollback.
    servers = []

    class Server:
        def __init__(self, argv, env, **kwargs):
            servers.append(env)

        def kill(self):
            pass

        def wait(self):
            pass

    monkeypatch.setattr(session.subprocess, "Popen", Server)
    monkeypatch.setattr(session, "save_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "seed_claude", lambda env, profile: None)
    monkeypatch.setattr(session, "Path", lambda path: tmp_path / path.lstrip("/"))
    monkeypatch.setattr(session, "start", lambda argv, profile, server: "w1:p1")
    monkeypatch.setattr(session, "submit", lambda text, deadline: None)
    monkeypatch.setattr(session, "watch", lambda schema, pane, agent: {"category": "Security fix"})
    session.run([agent], {"agent": agent, "auth_type": "api_key"}, {"PATH": "/usr/bin"}, "task", SCHEMA)
    assert servers[0].get("CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN") == ("1" if agent == "claude" else None)
