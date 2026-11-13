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


def test_triage_returns_the_raw_reply_without_schema_validation(tmp_path, monkeypatch):
    """Triage is one tool-less call: its reply text is the result, and application code validates it."""
    monkeypatch.setattr(workload, "WORK", tmp_path)
    monkeypatch.setattr(workload, "setup_auth", lambda p, env: None)
    monkeypatch.setattr(workload, "capabilities", lambda p, env, timeout: {
        "status": "ready", "models": [{"id": "m", "reasoning_efforts": []}]})
    replies, calls = ["Not JSON, and no schema check here.", "Leaked synthetic-key-not-real"], []

    def run(argv, env, data=None, timeout=1800, max_bytes=0, events=None):
        calls.append((argv, data, timeout))
        return 0, json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": replies[len(calls) - 1]}), ""

    monkeypatch.setattr(workload, "run_process", run)
    job = {"kind": "agent", "inputs": [], "prompt": "Triage this change.",
           "limits": {"input_bytes": 1024, "output_bytes": 1024, "timeout_seconds": 120},
           "output_schema": {"type": "object", "required": ["decision"]},
           "profile": {"agent": "claude", "provider_id": "claude", "auth_type": "api_key", "model_id": "m",
                       "operation": "commit_triage", "credential": {"api_key": "synthetic-key-not-real"}}}
    assert workload.execute(job) == {"result": {"reply": replies[0]}, "outputs": []}
    (argv, prompt, timeout), = calls
    assert argv[argv.index("--tools") + 1] == "" and timeout == 120
    assert prompt.endswith("You have no tools. Reply with only one JSON object matching the schema.")
    assert "result_json" not in prompt and '"required": ["decision"]' in prompt
    with pytest.raises(ValueError, match="credential material detected"):
        workload.execute(job)
