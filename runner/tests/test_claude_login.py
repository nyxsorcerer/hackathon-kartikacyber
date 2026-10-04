import json
import os
import queue
import sys
import threading

import pytest

from numen_runner import workload

CODE = "fixture-authorization-code#fixture-state"


@pytest.fixture
def claude_cli(tmp_path, monkeypatch):
    work = tmp_path / "workspace"
    work.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    home = private / ".claude"
    binary = tmp_path / "bin"
    binary.mkdir()
    cli = binary / "claude"
    # Mirrors the pinned CLI's manual flow: URL, unterminated prompt, one stdin line.
    cli.write_text(
        f"#!{sys.executable}\n"
        "import json,os,sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:]==['auth','login','--claudeai'], sys.argv\n"
        "home=Path(os.environ['CLAUDE_CONFIG_DIR'])\n"
        "if not home.is_dir():\n"
        "    sys.stderr.write('config dir missing\\n');sys.exit(2)\n"
        "sys.stdout.write('Opening browser to sign in\\u2026\\n')\n"
        "sys.stdout.write(\"If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&client_id=fixture&state=fixture-state\\n\")\n"
        "sys.stdout.write('Paste code here if prompted > ');sys.stdout.flush()\n"
        "code=sys.stdin.readline().strip()\n"
        f"if code!={CODE!r}:\n"
        "    print('Login failed: Request failed with status code 400');sys.exit(1)\n"
        "(home/'.credentials.json').write_text(json.dumps({'claudeAiOauth':{'accessToken':'fixture-claude-session-no-access'}}))\n"
        "print('Login successful.')\n"
    )
    cli.chmod(0o700)
    monkeypatch.setattr(workload, "WORK", work)
    monkeypatch.setattr(workload, "PRIVATE", private)
    env = {"PATH": str(binary) + os.pathsep + os.defpath, "CLAUDE_CONFIG_DIR": str(home)}
    return private, home, env


def start_login(env, monkeypatch, timeout=5):
    events, completed, errors = queue.Queue(), [], []
    monkeypatch.setattr(workload, "print", lambda value, **_: events.put(json.loads(value)["event"]), raising=False)

    def login():
        try:
            completed.append(workload.claude_login(env, timeout))
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=login)
    thread.start()
    return thread, events, completed, errors


def test_claude_login_shows_url_then_submits_operator_code(claude_cli, monkeypatch):
    private, home, env = claude_cli
    thread, events, completed, errors = start_login(env, monkeypatch)
    try:
        instruction = events.get(timeout=2)
        assert instruction == {"type": "login_instruction", "input_required": "authorization_code",
                               "verification_uri": "https://claude.com/cai/oauth/authorize?code=true&client_id=fixture&state=fixture-state"}
        assert thread.is_alive() and not completed
        (private / "login-code").write_text(CODE + "\n")
        assert events.get(timeout=2) == {"type": "login_instruction", "status": "code_submitted"}
    finally:
        thread.join(timeout=5)
    assert not errors
    assert completed[0]["result"] == {"status": "ready", "auth_type": "native_oauth"}
    assert completed[0]["credential"] == {"credentials_json": {"claudeAiOauth": {"accessToken": "fixture-claude-session-no-access"}}}
    assert home.stat().st_mode & 0o777 == 0o700
    assert not (private / "login-code").exists()
    assert events.empty()


def test_claude_login_reports_rejected_code(claude_cli, monkeypatch):
    private, _, env = claude_cli
    thread, events, _, errors = start_login(env, monkeypatch)
    events.get(timeout=2)
    (private / "login-code").write_text("wrong-authorization-code#fixture-state")
    thread.join(timeout=5)
    assert [str(e) for e in errors] == ["authorization code rejected or expired"]


def test_claude_login_rejects_malformed_code_without_forwarding(claude_cli, monkeypatch):
    private, _, env = claude_cli
    thread, events, _, errors = start_login(env, monkeypatch)
    events.get(timeout=2)
    (private / "login-code").write_text("fixture code; with spaces")
    thread.join(timeout=5)
    assert [str(e) for e in errors] == ["authorization code is malformed"]
    assert not (private / "login-code").exists()


def test_claude_login_times_out_without_code(claude_cli, monkeypatch):
    _, _, env = claude_cli
    thread, events, _, errors = start_login(env, monkeypatch, timeout=1)
    thread.join(timeout=5)
    assert [str(e) for e in errors] == ["native login timed out waiting for authorization code"]
