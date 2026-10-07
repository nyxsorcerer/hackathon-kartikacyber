import base64
import hashlib
import io
import tarfile
import pytest
from numen_runner import contracts
from numen_runner.contracts import RunRequest, input_files, safe_path, validate_outputs

@pytest.mark.parametrize("path", ["../x", "/x", "a/../x", "a\\b", "a//b"])
def test_rejects_unsafe_paths(path):
    with pytest.raises(ValueError):
        safe_path(path)


def test_limits_only_lower_and_credentials_required():
    with pytest.raises(ValueError):
        RunRequest(attempt_token="one", kind="probe", limits={"memory_mb": 99999})
    with pytest.raises(ValueError):
        RunRequest(attempt_token="one", kind="agent", profile={"operation": "commit_analysis", "model_id": "m"})
    assert RunRequest(attempt_token="one", kind="probe", limits={"memory_mb": 128}).bounds["memory_mb"] == 128


def test_output_integrity_and_aggregate_limit():
    data = b"hi"
    item = {"path": "report.md", "content_base64": base64.b64encode(data).decode(), "size": 2, "sha256": hashlib.sha256(data).hexdigest()}
    assert validate_outputs([item], 2) == [item]
    with pytest.raises(ValueError):
        validate_outputs([item, {**item, "path": "other.md"}], 3)
    with pytest.raises(ValueError):
        validate_outputs([{**item, "sha256": "wrong"}], 4)


def test_hidden_source_files_are_evidence_and_remote_schema_refs_are_denied():
    assert safe_path("source/.htaccess") == "source/.htaccess"
    with pytest.raises(ValueError):
        RunRequest(attempt_token="one", kind="probe", output_schema={"$ref":"file:///etc/passwd"})
    with pytest.raises(ValueError):
        RunRequest(attempt_token="one", kind="probe", limits={"memory_mb":0.5})


def source_archive(*members):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.type, info.size = kind, len(data)
            archive.addfile(info, io.BytesIO(data))
    return {"path": "source", "content_base64": base64.b64encode(payload.getvalue()).decode(), "archive": True}


def agent_request(inputs, kind="agent"):
    return RunRequest(attempt_token="one", kind=kind, inputs=inputs,
                      profile={"operation": "cve_analysis", "model_id": "m", "credential": {"api_key": "k"}})


def test_agent_source_archive_expands_regular_files_under_its_path():
    item = source_archive(("a.php", b"<?php", tarfile.REGTYPE), ("nested/b.js", b"js", tarfile.REGTYPE))
    agent_request([item, {"path": "skill/SKILL.md", "content_base64": "eA=="}])
    assert input_files([item], 1024) == [("source/a.php", b"<?php"), ("source/nested/b.js", b"js")]


@pytest.mark.parametrize("member", [("link", b"", tarfile.SYMTYPE), ("../escape", b"x", tarfile.REGTYPE),
                                    ("dir", b"", tarfile.DIRTYPE)])
def test_source_archive_rejects_links_escapes_and_directories(member):
    with pytest.raises(ValueError):
        agent_request([source_archive(member)])


def test_source_archive_is_agent_only_bounded_and_cannot_shadow_inputs(monkeypatch):
    item = source_archive(("a.php", b"x", tarfile.REGTYPE), ("b.php", b"y", tarfile.REGTYPE))
    with pytest.raises(ValueError):
        agent_request([item], kind="probe")
    with pytest.raises(ValueError):
        agent_request([item, {"path": "source/a.php", "content_base64": "eA=="}])
    with pytest.raises(ValueError):
        agent_request([{**item, "content_base64": base64.b64encode(b"not gzip").decode()}])
    monkeypatch.setattr(contracts, "ARCHIVE_FILES", 1)
    with pytest.raises(ValueError):
        agent_request([item])


def test_agent_runs_have_no_deadline_unless_requested():
    assert agent_request([]).bounds["timeout_seconds"] is None
    explicit = RunRequest(attempt_token="one", kind="agent", limits={"timeout_seconds": 60},
                          profile={"operation": "cve_analysis", "model_id": "m", "credential": {"api_key": "k"}})
    assert explicit.bounds["timeout_seconds"] == 60
    assert RunRequest(attempt_token="one", kind="probe").bounds["timeout_seconds"] == 1800


def test_build_is_limited_to_supported_agent_operations_and_raises_the_ceiling():
    agent = {"attempt_token":"t","kind":"agent","profile":{"operation":"cve_analysis","model_id":"m","credential":{"api_key":"k"}}}
    run = RunRequest(**agent, build=True, limits={"memory_mb":6144,"pids":2048})
    assert run.bounds["memory_mb"] == 6144 and run.bounds["pids"] == 2048
    # An ordinary agent run has no deadline; a build run keeps one, because its daemon is privileged.
    assert run.bounds["timeout_seconds"] == contracts.BUILD_MAXIMA["timeout_seconds"]
    assert RunRequest(**agent).bounds["timeout_seconds"] is None
    with pytest.raises(ValueError):  # The same limits exceed an ordinary run's ceiling.
        RunRequest(**agent, limits={"memory_mb":6144,"pids":2048})
    commit = RunRequest(**{**agent, "profile":{**agent["profile"], "operation":"commit_analysis"}}, build=True, limits={"memory_mb":6144,"pids":2048})
    assert commit.bounds == run.bounds
    with pytest.raises(ValueError):
        RunRequest(**{**agent, "profile":{**agent["profile"], "operation":"commit_triage"}}, build=True)
    with pytest.raises(ValueError):
        RunRequest(attempt_token="t", kind="lab", build=True)
