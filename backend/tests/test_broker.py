import base64
import io
import json
import tarfile

import httpx
import pytest
from numen.broker import Broker
from numen.config import Config
from numen.security import DomainError


def test_attempt_lookup_requires_positive_absence_and_resolves_running_identity():
    broker = Broker(Config())
    state = {"run_id": "known-run", "status": "running", "reconciled": False}
    broker.client = httpx.Client(
        base_url="http://broker",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=state)),
    )
    assert broker.lookup_attempt("attempt")["run_id"] == "known-run"
    state.update(run_id=None, status="absent", reconciled=True)
    assert broker.lookup_attempt("attempt") is None
    state["reconciled"] = False
    with pytest.raises(DomainError, match="authoritative"):
        broker.lookup_attempt("attempt")
    broker.client = httpx.Client(
        base_url="http://broker", transport=httpx.MockTransport(lambda _: httpx.Response(404))
    )
    with pytest.raises(DomainError):
        broker.lookup_attempt("attempt")


def test_agent_source_is_one_deterministic_archive_input(monkeypatch):
    bodies = []

    def http(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(202, json={"run_id": "run", "status": "queued"})

    broker = Broker(Config())
    broker.client = httpx.Client(base_url="http://broker", transport=httpx.MockTransport(http))
    # More source files than the runtime's 512 per-run inputs.
    source = {f"source/src/{index}.php": b"<?php // %d" % index for index in range(600)}
    broker.submit("one", "agent", files={**source, "skill/SKILL.md": b"skill"})
    broker.submit("one", "agent", files={"skill/SKILL.md": b"skill", **source})
    assert bodies[0] == bodies[1]
    skill, archive = bodies[0]["inputs"]
    assert skill["path"] == "skill/SKILL.md"
    assert archive["path"] == "source" and archive["archive"] is True
    payload = io.BytesIO(base64.b64decode(archive["content_base64"]))
    with tarfile.open(fileobj=payload, mode="r:gz") as tar:
        assert {member.name: tar.extractfile(member).read() for member in tar} == {
            path.removeprefix("source/"): data for path, data in source.items()
        }
    broker.submit("two", "probe", files={"source/recipe.py": b"x"})
    assert bodies[-1]["inputs"] == [{"path": "source/recipe.py", "content_base64": "eA=="}]
    monkeypatch.setattr("numen.broker.MAX_SOURCE_FILES", 599)
    with pytest.raises(DomainError, match="narrower source path"):
        broker.submit("three", "agent", files=source)


def test_agent_runs_are_submitted_and_awaited_without_a_deadline(monkeypatch):
    import numen.broker as broker_module
    from types import SimpleNamespace

    bodies, states = [], iter(["running", "running", "succeeded"])

    def http(request):
        if request.method == "POST":
            bodies.append(json.loads(request.content))
            return httpx.Response(202, json={"run_id": "run", "status": "queued"})
        return httpx.Response(200, json={"run_id": "run", "status": next(states)})

    broker = Broker(Config())
    broker.client = httpx.Client(base_url="http://broker", transport=httpx.MockTransport(http))
    broker.submit("agent-attempt", "agent")
    broker.submit("probe-attempt", "probe")
    assert "timeout_seconds" not in bodies[0]["limits"]
    assert bodies[1]["limits"]["timeout_seconds"] == 600
    # Each clock reading jumps 1000 s, past the 900 s deadline other run kinds keep.
    clock = iter(range(0, 10**6, 1000))
    monkeypatch.setattr(
        broker_module, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None)
    )
    assert broker.wait("run", lambda: None, lambda _: None, deadline=None)["status"] == "succeeded"
