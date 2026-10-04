import json
import os
import queue
import sys
import threading

import pytest

from numen_runner import workload


@pytest.fixture
def device_cli(tmp_path, monkeypatch):
    work = tmp_path / "workspace"
    work.mkdir()
    home = tmp_path / "private" / ".codex"
    binary = tmp_path / "bin"
    binary.mkdir()
    cli = binary / "codex"
    cli.write_text(
        f"#!{sys.executable}\n"
        "import json,os,time,sys\n"
        "from pathlib import Path\n"
        "home=Path(os.environ['CODEX_HOME'])\n"
        "if not home.is_dir():\n"
        "    sys.stderr.write('CODEX_HOME does not exist\\n');sys.exit(2)\n"
        "sys.stdout.write('Open this page:\\nhttps://auth.openai.com/codex/device\\nABCD-EFGH\\n');sys.stdout.flush()\n"
        "while not Path('finish').exists(): time.sleep(.02)\n"
        "(home/'auth.json').write_text(json.dumps({'tokens':{'access_token':'fixture-session-no-real-access'}}))\n"
    )
    cli.chmod(0o700)
    monkeypatch.setattr(workload, "WORK", work)
    env = {"PATH": str(binary) + os.pathsep + os.defpath, "CODEX_HOME": str(home)}
    return work, home, env


def test_device_login_initializes_private_home_before_native_cli(device_cli, capsys):
    work, home, env = device_cli
    (work / "finish").touch()
    result = workload.codex_device_login(env, 3)
    assert home.is_dir()
    assert home.stat().st_mode & 0o777 == 0o700
    assert result["result"]["status"] == "ready"
    assert result["credential"]["auth_json"]["tokens"]["access_token"] == "fixture-session-no-real-access"
    assert "fixture-session-no-real-access" not in capsys.readouterr().out


def test_device_instructions_arrive_before_cli_finishes(device_cli, monkeypatch):
    work, home, env = device_cli
    home.mkdir(parents=True, mode=0o700)
    events = queue.Queue()
    completed = []
    errors = []
    monkeypatch.setattr(workload, "print", lambda value, **_: events.put(json.loads(value)), raising=False)

    def login():
        try:
            completed.append(workload.codex_device_login(env, 4))
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=login)
    thread.start()
    try:
        observed = [events.get(timeout=1.5), events.get(timeout=1.5)]
        assert thread.is_alive()
        assert not completed
        assert any(item["event"].get("verification_uri") == "https://auth.openai.com/codex/device" for item in observed)
        assert any(item["event"].get("user_code") == "ABCD-EFGH" for item in observed)
    finally:
        (work / "finish").touch()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert not errors
    assert completed[0]["result"]["status"] == "ready"
