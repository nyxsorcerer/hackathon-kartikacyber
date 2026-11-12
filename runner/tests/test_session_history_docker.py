"""Real Engine proof of history surviving both workload exit and forced cancellation."""
import os
import uuid

import pytest

from numen_runner.engine import DockerEngine, INSTANCE, LABEL

pytestmark = pytest.mark.skipif(os.getenv("NUMEN_DOCKER_TESTS") != "1", reason="explicit Docker Engine verification only")


@pytest.mark.parametrize("agent,path", [
    ("pi", "session-transcripts/pi/session.jsonl"),
    ("claude", ".claude/projects/numen/session.jsonl"),
    ("codex", ".codex/sessions/2026/10/05/rollout-session.jsonl"),
])
@pytest.mark.parametrize("cancel", [False, True])
def test_full_native_history_survives_container_stop_and_private_archive_transport(agent, path, cancel):
    engine = DockerEngine()
    run_id = str(uuid.uuid4())
    labels = {LABEL: run_id, INSTANCE: engine.instance}
    image = "asset-monitor-runner-test:0.1.0"
    script = '''import json,time
from pathlib import Path
from numen_runner.session_history import save_state
agent,path,cancel=ARGS
save_state(agent, "LAST LIVE VIEW")
target=Path('/home/job')/path
target.parent.mkdir(parents=True,exist_ok=True)
message={'role':'assistant','content':[{'type':'text','text':'FIRST RECORD\\n'+'line\\n'*900000+'LAST RECORD'}]}
record={'type':'response_item','payload':{'type':'message',**message}} if agent=='codex' else {'type':'message','message':message}
target.write_text(json.dumps(record)+'\\n')
Path('/home/job/ready').touch()
if cancel: time.sleep(30)
'''.replace("ARGS", repr((agent, path, cancel)))
    try:
        home = engine.prepare_session_home(run_id, image, labels)
        container = engine.client.containers.create(image, ["python", "-c", script],
            network_mode="none", user="10001:10001", read_only=True, cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"], labels=labels,
            volumes={home.name:{"bind":"/home/job","mode":"rw"}}, use_config_proxy=False)
        engine.sessions[run_id] = container
        engine.session_homes[run_id] = (home.name, image, labels)
        container.start()
        if cancel:
            import time
            deadline = time.monotonic() + 10
            while container.exec_run(["test", "-f", "/home/job/ready"]).exit_code:
                assert time.monotonic() < deadline
                time.sleep(.05)
            container.kill()
        container.wait(timeout=15)
        assert container.logs() == b""  # History never enters the workload's main log.
        state = engine.session(run_id, "read")
        assert "FIRST RECORD" in state["screen"] and "LAST RECORD" in state["screen"]
        assert state["screen"].count("line\n") == 900000
        assert len(state["screen"]) > 4 * 1024 * 1024
        assert state["screen"].endswith("LAST LIVE VIEW") and state["live"] is False
    finally:
        engine.cleanup(run_id)
    assert not engine.client.containers.list(all=True, filters={"label": f"{LABEL}={run_id}"})
    assert not engine.client.volumes.list(filters={"label": f"{LABEL}={run_id}"})
