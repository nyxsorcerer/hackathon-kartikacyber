import time
import json

import pytest
from fastapi.testclient import TestClient

from numen_runner.broker import create_app
from numen_runner.engine import RuntimeFailure
from numen_runner.engine import DockerEngine
from numen_runner.session_history import read_history, save_state


@pytest.mark.parametrize("outcome", ["succeeded", "failed", "cancelled"])
def test_complete_session_is_redacted_retained_before_cleanup_and_survives_restart(tmp_path, outcome):
    text = "FIRST\n" + "output\n" * 1200 + "synthetic-private-key\nsynthetic-\nprivate-key\nLAST"

    class Engine:
        removed = False

        def run(self, run_id, request, cancelled, event):
            if outcome == "cancelled":
                app.state.store.change(run_id, status="cancelling")
            if outcome != "succeeded":
                raise RuntimeFailure("cancelled" if outcome == "cancelled" else "timeout", "Stopped.")
            return {"result": {}, "outputs": []}

        def session(self, run_id, command):
            assert not self.removed, "session must be retained before cleanup"
            return {"agent": "claude", "agent_status": "idle", "held": False, "screen": text}

        def cleanup(self, run_id):
            self.removed = True

    engine = Engine()
    token = "session-history-test-token"
    headers = {"X-Broker-Token": token}
    app = create_app(token, tmp_path, engine=engine)
    with TestClient(app) as client:
        run = client.post("/internal/runs", headers=headers, json={
            "attempt_token": outcome, "kind": "agent",
            "profile": {"agent": "claude", "provider_id": "claude", "operation": "commit_analysis", "model_id": "m",
                        "credential": {"api_key": "synthetic-private-key"}},
        }).json()["run_id"]
        deadline = time.monotonic() + 3
        while client.get(f"/internal/runs/{run}", headers=headers).json()["status"] not in {"succeeded", "failed", "cancelled"}:
            assert time.monotonic() < deadline
            time.sleep(.01)
        response = client.get(f"/internal/runs/{run}/session", headers=headers)
        assert response.status_code == 200
        state = response.json()
        assert state["screen"].startswith("FIRST\n") and state["screen"].endswith("LAST")
        assert state["screen"].count("output\n") == 1200
        assert "synthetic-private-key" not in state["screen"] and "[redacted]" in state["screen"]
        assert "synthetic-\nprivate-key" not in state["screen"]
        assert state["live"] is False
        assert client.post(f"/internal/runs/{run}/session", headers=headers, json={"action": "hold"}).status_code == 409
    for file in tmp_path.rglob("*.json"):
        assert "synthetic-private-key" not in file.read_text()
    restarted = create_app(token, tmp_path, engine=engine, execute=False)
    with TestClient(restarted) as client:
        assert client.get(f"/internal/runs/{run}/session", headers=headers).json() == state


@pytest.mark.parametrize("agent,path", [
    ("pi", "session-transcripts/pi/session.jsonl"),
    ("claude", ".claude/projects/numen/session.jsonl"),
    ("codex", ".codex/sessions/2026/10/05/rollout-session.jsonl"),
])
def test_native_history_includes_first_last_and_large_tool_output(agent, path, tmp_path):
    save_state(agent, "CURRENT STREAMING TAIL", home=tmp_path)
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    first = {"role": "user", "content": [{"type": "text", "text": "FIRST MESSAGE"}]}
    last = {"role": "assistant", "content": [{"type": "text", "text": "LAST MESSAGE"}]}
    tool = {"role": "toolResult", "content": [{"type": "text", "text": "tool output\n" * 400_000}]}
    with target.open("w") as handle:
        for message in (first, tool, last):
            record = {"type": "response_item", "payload": {"type": "message", **message}} if agent == "codex" else {"type": "message", "message": message}
            handle.write(json.dumps(record) + "\n")
        handle.write('{"partial":')
    state = read_history(tmp_path)
    assert "FIRST MESSAGE" in state["screen"] and "LAST MESSAGE" in state["screen"]
    assert state["screen"].count("tool output\n") == 400_000
    assert state["screen"].endswith("CURRENT STREAMING TAIL")
    assert len(state["screen"]) > 4 * 1024 * 1024
    assert state["live"] is False


def test_native_history_refuses_linked_credential_paths(tmp_path):
    save_state("pi", home=tmp_path)
    directory = tmp_path / "session-transcripts/pi"
    directory.mkdir(parents=True)
    private = tmp_path / "auth.json"
    private.write_text('{"private": "synthetic-credential"}\n')
    (directory / "session.jsonl").symlink_to(private)
    with pytest.raises(ValueError, match="linked path"):
        read_history(tmp_path)


def test_claude_large_tool_sidecars_are_read_in_full_from_the_known_root(tmp_path):
    save_state("claude", home=tmp_path)
    root = tmp_path / ".claude/projects/numen/id/tool-results"
    root.mkdir(parents=True)
    (root / "tool-1.txt").write_text("FIRST TOOL LINE\n" + "line\n" * 1500 + "LAST TOOL LINE")
    (root / "tool-2.json").write_text(json.dumps([{"type": "text", "text": "COMPLETE JSON TOOL RESULT"}]))
    state = read_history(tmp_path)
    assert "FIRST TOOL LINE" in state["screen"] and "LAST TOOL LINE" in state["screen"]
    assert state["screen"].count("line\n") == 1500
    assert "COMPLETE JSON TOOL RESULT" in state["screen"]


def test_steering_accepts_success_without_a_json_body_but_reads_require_state():
    from types import SimpleNamespace

    class Container:
        status = "running"

        def reload(self):
            pass

        def exec_run(self, *_args, **_kwargs):
            return SimpleNamespace(exit_code=0, output=b"")

    engine = DockerEngine(client=object())
    engine.sessions["run"] = Container()
    assert engine.session("run", "send", '{"action":"hold"}') == {}
    with pytest.raises(RuntimeFailure, match="invalid state"):
        engine.session("run", "read")


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_late_live_read_cannot_overwrite_final_history_or_bypass_redaction(tmp_path, cleanup_fails):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    started, finish, reading, release = (threading.Event() for _ in range(4))

    class Engine:
        reads = 0

        def run(self, *_args):
            started.set()
            assert finish.wait(3)
            return {"result": {}, "outputs": []}

        def session(self, *_args):
            self.reads += 1
            if self.reads == 1:
                reading.set()
                assert release.wait(3)
                screen = "OLD synthetic-private-key"
            else:
                screen = "FIRST\nFINAL synthetic-private-key\nLAST"
            return {"agent": "claude", "agent_status": "idle", "held": False, "screen": screen}

        def cleanup(self, *_args):
            if cleanup_fails:
                raise RuntimeFailure("engine_unavailable", "Cleanup is pending.")

    token = "session-history-test-token"
    headers = {"X-Broker-Token": token}
    app = create_app(token, tmp_path, engine=Engine())
    with TestClient(app) as client, ThreadPoolExecutor() as executor:
        run = client.post("/internal/runs", headers=headers, json={
            "attempt_token": "late-read", "kind": "agent",
            "profile": {"agent": "claude", "provider_id": "claude", "operation": "commit_analysis", "model_id": "m",
                        "credential": {"api_key": "synthetic-private-key"}},
        }).json()["run_id"]
        assert started.wait(1)
        url = f"/internal/runs/{run}/session"
        future = executor.submit(client.get, url, headers=headers)
        assert reading.wait(1)
        finish.set()
        deadline = time.monotonic() + 3
        status = "cancelling" if cleanup_fails else "succeeded"
        while client.get(f"/internal/runs/{run}", headers=headers).json()["status"] != status:
            assert time.monotonic() < deadline
            time.sleep(.01)
        release.set()
        state = future.result(timeout=3).json()
        assert state["screen"] == "FIRST\nFINAL [redacted]\nLAST" and state["live"] is False
        assert client.get(url, headers=headers).json() == state
    for file in tmp_path.rglob("*.json"):
        assert "synthetic-private-key" not in file.read_text()
