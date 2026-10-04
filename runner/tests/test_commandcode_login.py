import json
import os
import queue
import sys
import threading

import pytest

from numen_runner import workload
from numen_runner.contracts import RunRequest

KEY = "user_fixture-commandcode-key"
URL = "https://commandcode.ai/studio/auth/cli?callback=http%3A%2F%2Flocalhost%3A5959%2Fcallback&state=fixture"


@pytest.fixture
def login_script(tmp_path, monkeypatch):
    work = tmp_path / "workspace"
    work.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    agent_dir = private / ".pi" / "agent"
    script = tmp_path / "pi-commandcode-login.py"
    # Mirrors pi-commandcode-login.mjs: Studio URL on stdout, one stdin line, pi auth.json on success.
    script.write_text(
        "import json,os,sys\n"
        "from pathlib import Path\n"
        "home=Path(os.environ['PI_CODING_AGENT_DIR'])\n"
        "assert home.is_dir()\n"
        f"print({URL!r},flush=True)\n"
        "key=sys.stdin.readline().strip()\n"
        f"if key!={KEY!r}:\n"
        "    sys.stderr.write('Invalid Command Code API key\\n');sys.exit(1)\n"
        "(home/'auth.json').write_text(json.dumps({'commandcode':{'refresh':key,'access':key,'expires':2106459876554,'type':'oauth'}}))\n"
    )
    monkeypatch.setattr(workload, "WORK", work)
    monkeypatch.setattr(workload, "PRIVATE", private)
    monkeypatch.setattr(workload, "COMMANDCODE_LOGIN", [sys.executable, str(script)])
    return private, agent_dir, {"PATH": os.defpath, "PI_CODING_AGENT_DIR": str(agent_dir)}


def start_login(env, monkeypatch):
    events, completed, errors = queue.Queue(), [], []
    monkeypatch.setattr(workload, "print", lambda value, **_: events.put(json.loads(value)["event"]), raising=False)

    def login():
        try:
            completed.append(workload.commandcode_login(env, 5))
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=login)
    thread.start()
    return thread, events, completed, errors


def test_commandcode_login_shows_studio_url_then_submits_pasted_key(login_script, monkeypatch):
    private, agent_dir, env = login_script
    thread, events, completed, errors = start_login(env, monkeypatch)
    try:
        assert events.get(timeout=2) == {"type": "login_instruction", "verification_uri": URL, "input_required": "api_key"}
        (private / "login-code").write_text(KEY)
        assert events.get(timeout=2) == {"type": "login_instruction", "status": "code_submitted"}
    finally:
        thread.join(timeout=5)
    assert not errors
    assert completed[0]["result"] == {"status": "ready", "auth_type": "native_oauth"}
    entry = completed[0]["credential"]["auth_json"]["commandcode"]
    assert entry["type"] == "oauth" and entry["access"] == KEY
    assert agent_dir.stat().st_mode & 0o777 == 0o700
    assert events.empty()


def test_commandcode_login_reports_rejected_key(login_script, monkeypatch):
    private, _, env = login_script
    thread, events, _, errors = start_login(env, monkeypatch)
    events.get(timeout=2)
    (private / "login-code").write_text("user_wrong-commandcode-key")
    thread.join(timeout=5)
    assert [str(e) for e in errors] == ["Command Code API key rejected"]


def test_native_commandcode_credential_maps_to_plugin_environment():
    profile = {"agent": "pi", "provider_id": "commandcode", "auth_type": "native_oauth",
               "credential": {"auth_json": {"commandcode": {"type": "oauth", "access": KEY, "refresh": KEY}}}}
    env = {}
    workload.setup_auth(profile, env)
    assert env == {"COMMAND_CODE_API_KEY": KEY}
    with pytest.raises(ValueError, match="native Command Code credential is missing"):
        workload.setup_auth({**profile, "credential": {"auth_json": {}}}, {})
    assert workload.refreshed_credential({"kind": "agent", "profile": profile}) is None


def test_pi_native_login_is_accepted_only_for_commandcode_with_enabled_plugin():
    profile = {"agent": "pi", "provider_id": "commandcode", "auth_type": "native_oauth"}
    RunRequest(attempt_token="cc-login", kind="account_login", profile={**profile, "enabled_plugins": ["pi-commandcode-provider"]})
    for rejected in ({**profile, "enabled_plugins": []}, {**profile, "provider_id": "openai"}):
        with pytest.raises(ValueError):
            RunRequest(attempt_token="cc-login", kind="account_login", profile=rejected)
