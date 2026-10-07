import io
import json
import pytest
from numen_runner import workload

def test_native_credentials_never_enter_stdout_and_private_ingress_deleted(tmp_path,monkeypatch,capsys):
    monkeypatch.setattr(workload,"WORK",tmp_path)
    monkeypatch.setattr(workload,"PRIVATE",tmp_path/"private")
    monkeypatch.setattr(workload,"execute",lambda _: {"result":{"status":"ready"},"credential":{"auth_json":{"tokens":{"access_token":"sensitive-token-value"}}},"outputs":[]})
    monkeypatch.setattr(workload.sys,"stdin",io.TextIOWrapper(io.BytesIO(b'{}\n')))
    (tmp_path/'credential-ack').write_text('ok')
    workload.main()
    output=capsys.readouterr().out
    assert 'sensitive-token-value' not in output
    assert json.loads(output.splitlines()[0])=={"credential_ready":True}
    assert 'credential' not in json.loads(output.splitlines()[1])['envelope']
    assert not (tmp_path/'private'/'credential-ingress.json').exists()
    assert json.loads(output.splitlines()[1])['credential_updated'] is True


def test_run_process_without_deadline_waits_for_completion(tmp_path,monkeypatch):
    monkeypatch.setattr(workload,"WORK",tmp_path)
    code,out,_=workload.run_process([workload.sys.executable,"-c","import time;time.sleep(1.2);print('done')"],{},timeout=None)
    assert (code,out.strip())==(0,"done")


@pytest.mark.parametrize("error,message",[
    (ValueError("subprocess output exceeded byte limit"),"Subprocess output exceeded byte limit."),
    (KeyError("unexpected"),"Workload failed; required runtime or connection unavailable (KeyError)."),
])
def test_internal_failures_report_their_cause(tmp_path,monkeypatch,capsys,error,message):
    monkeypatch.setattr(workload,"WORK",tmp_path)
    monkeypatch.setattr(workload,"PRIVATE",tmp_path/"private")
    def fail(_):
        raise error
    monkeypatch.setattr(workload,"execute",fail)
    monkeypatch.setattr(workload.sys,"stdin",io.TextIOWrapper(io.BytesIO(b'{}\n')))
    try:
        workload.main()
    except SystemExit:
        pass
    failure=json.loads(capsys.readouterr().out.splitlines()[-1])["failure"]
    assert failure=={"code":"workload_failed","message":message}


@pytest.mark.parametrize("loaded", [True, False])
def test_build_prompt_states_the_base_outcome_and_builds_in_both_branches(loaded, monkeypatch, tmp_path):
    """The conditional once concatenated a literal onto a call and raised TypeError at run time."""
    from numen_runner import workload

    job = {
        "kind": "agent", "prompt": "Perform Numen operation cve_analysis.", "build": True,
        "lab_base_loaded": loaded, "output_schema": {"type": "object"}, "inputs": [],
        "inputs_materialized": True,
        "limits": {"timeout_seconds": 10800, "memory_mb": 1024, "cpus": 1, "pids": 128,
                   "output_bytes": 1024, "input_bytes": 1024},
        "profile": {"agent": "pi", "provider_id": "openai", "auth_type": "api_key",
                    "model_id": "m", "operation": "cve_analysis", "credential": {"api_key": "k"},
                    "enabled_plugins": [], "reasoning_effort": None},
    }
    seen = {}

    monkeypatch.setattr(workload, "setup_auth", lambda *_: None)
    monkeypatch.setattr(workload, "capabilities", lambda *_a, **_k: {
        "status": "ready", "models": [{"id": "m", "reasoning_efforts": []}]})
    monkeypatch.setattr(workload, "output_files", lambda *_a, **_k: [])
    monkeypatch.setattr(workload, "agent_result", lambda *_a, **_k: {"ok": True})

    def capture(argv, env, prompt=None, timeout=None, events=None):
        seen["prompt"] = prompt
        return 0, "{}", b""

    monkeypatch.setattr(workload, "run_process", capture)
    monkeypatch.setattr(workload, "WORK", tmp_path)
    workload.execute(job)
    prompt = seen["prompt"]
    assert "DOCKER_HOST" in prompt and "/workspace/share" in prompt
    assert ("is already loaded" in prompt) is loaded
    assert ("NOT available" in prompt) is (not loaded)
    assert "10800 seconds" in prompt
