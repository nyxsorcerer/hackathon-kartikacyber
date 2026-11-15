"""B04: Enrollment, agent requests and signed messages, end to end through the agent listener
(numen.ingress.agent_app on the dashboard's database), application code (numen.servers, as the
scheduler runs it) and the Server files API. Requests are signed as agent/PROTOCOL.md says."""
import base64
import hashlib
import json
import os
import secrets
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from numen import agent_wire, ingress, servers
from numen.models import Agent, AgentMessage, AgentRequest, DashboardKey, EnrollmentCode, Job, now
from numen.security import Vault
from conftest import application

POLL = "/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0"


class AgentClient:
    """One On-server agent with its own Agent key, speaking to the agent listener."""

    def __init__(self, listener, agent_id):
        self.client, self.agent_id = TestClient(listener), agent_id
        self.seed = secrets.token_bytes(32)
        self.public_key = agent_wire.public_key(self.seed)

    def send(self, method, target, body=None, timestamp=None, nonce=None, seed=None, digest=None, agent_id=None):
        raw = b"" if body is None else body if isinstance(body, bytes) else json.dumps(body).encode()
        timestamp = int(time.time()) if timestamp is None else timestamp
        nonce, sha = nonce or secrets.token_hex(16), hashlib.sha256(raw).hexdigest()
        signed = agent_wire.signed_bytes(method, target, timestamp, nonce, sha)
        headers = {"X-Agent-Id": agent_id or self.agent_id, "X-Agent-Timestamp": str(timestamp),
                   "X-Agent-Nonce": nonce, "X-Agent-Content-SHA256": digest or sha,
                   "X-Agent-Signature": base64.b64encode(
                       Ed25519PrivateKey.from_private_bytes(seed or self.seed).sign(signed)).decode()}
        if raw:
            headers["Content-Type"] = "application/json"
        response = self.client.request(method, target, content=raw, headers=headers)
        return response.status_code, response.json()

    def enroll(self, code, **body):
        return self.send("POST", "/agent/v1/enroll", {
            "agent_id": self.agent_id, "enrollment_code": code, "public_key": self.public_key,
            "allowed_paths": ["/var/www/html"], "version": "0.1.0", "os": "linux", "arch": "amd64", **body})

    def poll(self, **options):
        return self.send("GET", POLL, **options)


@pytest.fixture
def stand(system):
    app, client, config = system
    listener = ingress.agent_app(app.state.factory)
    ident = application(client)["id"]

    def add(name="web-1"):
        added = client.post(f"/api/applications/{ident}/agents", json={"name": name, "url": "https://10.0.0.5:8792"})
        assert added.status_code == 201, added.text
        enrollment = added.json()["enrollment"]
        return AgentClient(listener, enrollment["agent_id"]), enrollment

    agent, enrollment = add()
    return SimpleNamespace(client=client, config=config, factory=app.state.factory, listener=listener,
                           application_id=ident, agent=agent, enrollment=enrollment, add=add)


def process(stand):
    servers.process_agent_requests(stand.factory, stand.config.artifact_root)


def shown(stand, agent_id=None):
    """The agent as the Server files tab lists it."""
    listed = stand.client.get(f"/api/applications/{stand.application_id}/agents").json()
    return next(item for item in listed["items"] if item["id"] == (agent_id or stand.agent.agent_id))


def outcomes(stand):
    with stand.factory() as db:
        return [row.outcome for row in db.scalars(select(AgentRequest).order_by(AgentRequest.received_at))]


def count(stand, model):
    with stand.factory() as db:
        return db.scalar(select(func.count()).select_from(model))


def enrolled(stand):
    """Enrolls stand.agent and confirms its fingerprint."""
    assert stand.agent.enroll(stand.enrollment["code"]) == (202, {"status": "pending"})
    process(stand)
    confirmed = stand.client.post(f"/api/agents/{stand.agent.agent_id}/confirmations",
                                  json={"fingerprint": agent_wire.fingerprint(stand.agent.public_key)})
    assert confirmed.status_code == 200, confirmed.text
    return confirmed.json()


def payload(envelope):
    return json.loads(base64.b64decode(envelope["payload"]))


def test_the_enroll_command_and_code_are_shown_once(stand):
    """B04: the enroll command holds the listener URL, the TLS pin, the Dashboard public key and
    key id and the agent id; the code is <id>.<160 bits in base32>, and only its hash is kept."""
    enrollment, agent_id = stand.enrollment, stand.agent.agent_id
    with stand.factory() as db:
        key = db.scalar(select(DashboardKey))
        code = db.scalar(select(EnrollmentCode))
    code_id, secret = enrollment["code"].split(".")
    assert (code.id, len(secret), code.agent_id) == (code_id, 32, agent_id)
    assert code.secret_hash == hashlib.sha256(secret.encode()).hexdigest()
    assert timedelta(minutes=59) < code.expires_at - code.created_at <= timedelta(hours=1)
    assert enrollment["command"] == (
        f"asset-monitor-agent enroll --url https://10.0.0.5:8792 --tls-pin {'ab' * 32} --dashboard-key"
        f" {key.public_key} --key-id {key.id} --agent-id {agent_id} --allow /var/www/html")
    assert (enrollment["dashboard_key"], enrollment["key_id"], enrollment["tls_pin"]) == (
        key.public_key, key.id, "ab" * 32)
    listed = stand.client.get(f"/api/applications/{stand.application_id}/agents").json()
    assert listed["agent_url"] == "https://127.0.0.1:8792"
    assert secret not in json.dumps(listed) and code_id not in json.dumps(listed)
    # The Dashboard key's private half is stored only encrypted under NUMEN_SIGNING_KEY.
    seed = base64.b64decode(Vault(os.environ["NUMEN_SIGNING_KEY"]).decrypt(key.private_key))
    assert agent_wire.public_key(seed) == key.public_key
    assert base64.b64encode(seed).decode() not in key.private_key
    for url in ("http://10.0.0.5:8792", "https://10.0.0.5:8792/agent", "https://u:p@10.0.0.5", "https://h?x=1"):
        response = stand.client.post(f"/api/applications/{stand.application_id}/agents", json={"name": "x", "url": url})
        assert response.status_code == 422, url


def test_an_enrollment_code_works_once_and_not_after_an_hour(stand):
    """AC-B04: the listener only stores the Enrollment; application code checks the code, spends
    it and binds the key as pending. A used code, a wrong secret and an expired code are refused."""
    agent = stand.agent
    code_id = stand.enrollment["code"].split(".")[0]
    # A wrong secret passes the listener, which checks only the code id, and is refused later.
    assert agent.enroll(code_id + "." + "A" * 32) == (202, {"status": "pending"})
    assert shown(stand)["status"] == "awaiting_enrollment"
    process(stand)
    row = shown(stand)
    assert (row["status"], row["fingerprint"], row["last_refusal"]["reason"]) == (
        "awaiting_enrollment", None, "enrollment_refused")
    assert agent.enroll(stand.enrollment["code"]) == (202, {"status": "pending"})
    process(stand)
    row = shown(stand)
    assert (row["status"], row["fingerprint"], row["allowed_paths"]) == (
        "pending", agent_wire.fingerprint(agent.public_key), ["/var/www/html"])
    assert (row["version"], row["os"], row["arch"]) == ("0.1.0", "linux", "amd64")
    # The code is spent: a second Enrollment, with a new Agent key, is refused at the listener.
    again = AgentClient(stand.listener, agent.agent_id)
    assert again.enroll(stand.enrollment["code"]) == (401, {"error": "enrollment_refused"})
    assert shown(stand)["fingerprint"] == agent_wire.fingerprint(agent.public_key)

    late, enrollment = stand.add("web-2")
    with stand.factory.begin() as db:
        db.execute(update(EnrollmentCode).where(EnrollmentCode.agent_id == late.agent_id)
                   .values(expires_at=now() - timedelta(seconds=1)))
    assert late.enroll(enrollment["code"]) == (401, {"error": "enrollment_refused"})
    # Expired after the listener stored it: application code refuses it by the received time.
    other, enrollment = stand.add("web-3")
    assert other.enroll(enrollment["code"]) == (202, {"status": "pending"})
    with stand.factory.begin() as db:
        db.execute(update(EnrollmentCode).where(EnrollmentCode.agent_id == other.agent_id)
                   .values(expires_at=now() - timedelta(hours=1)))
    process(stand)
    assert shown(stand, other.agent_id)["status"] == "awaiting_enrollment"
    assert shown(stand, late.agent_id)["status"] == "awaiting_enrollment"


def test_a_pending_agent_starts_nothing_and_gets_nothing_signed(stand):
    """AC-B04: until the Operator confirms the fingerprint, a poll answers nothing, a report starts
    nothing and nothing is signed. A wrong fingerprint does not enroll it."""
    agent = stand.agent
    assert agent.enroll(stand.enrollment["code"])[0] == 202
    process(stand)
    jobs = count(stand, Job)
    assert agent.poll() == (200, {"configuration": None, "commands": [], "wanted": None})
    assert agent.send("POST", "/agent/v1/report", {"sequence": 1, "config_sequence": 1, "roots": []}) == (202, {"status": "accepted"})
    process(stand)
    assert {"status": "refused", "reason": "agent_pending"} in outcomes(stand)
    row = shown(stand)
    assert (row["status"], row["report_sequence"], row["last_refusal"]["reason"]) == ("pending", 0, "agent_pending")
    assert row["last_seen_at"]  # a verified poll
    assert stand.client.post(f"/api/agents/{agent.agent_id}/rescans").status_code == 409
    wrong = stand.client.post(f"/api/agents/{agent.agent_id}/confirmations", json={"fingerprint": "sha256:" + "0" * 64})
    assert wrong.status_code == 409
    assert (count(stand, AgentMessage), count(stand, Job)) == (0, jobs)
    assert shown(stand)["status"] == "pending"


def test_confirmation_signs_a_configuration_and_commands_the_agent_can_verify(stand):
    """B04: Confirm fingerprint enrolls the agent and signs its first configuration, whose Watched
    roots are its Allowed paths, with the Dashboard key; the poll returns it. A rescan command
    expires after 15 minutes, and results come back through verified requests."""
    agent, key = stand.agent, stand.enrollment["dashboard_key"]
    row = enrolled(stand)
    assert (row["status"], row["watched_roots"], row["key_id"]) == (
        "enrolled", ["/var/www/html"], stand.enrollment["key_id"])
    status, answer = agent.poll()
    assert status == 200 and answer["commands"] == [] and answer["wanted"] is None
    envelope = answer["configuration"]
    assert envelope["key_id"] == stand.enrollment["key_id"]
    assert agent_wire.verify(key, envelope["signature"],
                             agent_wire.MESSAGE_PREFIX + base64.b64decode(envelope["payload"]))
    message = payload(envelope)
    assert abs(message.pop("issued_at") - time.time()) < 60
    assert message == {"v": 1, "type": "configuration", "agent_id": agent.agent_id, "key_id": stand.enrollment["key_id"],
                       "sequence": 1, "expires_at": 0, "body": {
                           "watched_roots": ["/var/www/html"], "report_interval_seconds": 172800,
                           "poll_interval_seconds": 2}}
    assert agent.send("POST", "/agent/v1/result", {"type": "configuration", "sequence": 1, "status": "done"})[0] == 202
    process(stand)
    row = shown(stand)
    assert (row["configuration"]["status"], row["config_sequence"]) == ("done", 1)
    assert row["poll"] == {"config_sequence": 0, "command_sequence": 0, "report_sequence": 0}

    queued = stand.client.post(f"/api/agents/{agent.agent_id}/rescans")
    assert queued.status_code == 202, queued.text
    command = queued.json()
    (envelope,) = agent.poll()[1]["commands"]
    message = payload(envelope)
    assert agent_wire.verify(key, envelope["signature"], agent_wire.MESSAGE_PREFIX + base64.b64decode(envelope["payload"]))
    assert (message["type"], message["sequence"], message["expires_at"] - message["issued_at"]) == ("command", 2, 900)
    assert message["body"] == {"command_id": command["id"], "name": "rescan"}
    done = {"type": "command", "sequence": 2, "command_id": command["id"], "name": "rescan", "status": "done"}
    assert agent.send("POST", "/agent/v1/result", done)[0] == 202
    # After an agent restart one not_newer refusal may still arrive; a done command stays done.
    assert agent.send("POST", "/agent/v1/result", {**done, "status": "refused", "reason": "not_newer"})[0] == 202
    process(stand)
    (listed,) = shown(stand)["commands"]
    assert (listed["id"], listed["name"], listed["status"], listed["result"]) == (command["id"], "rescan", "done", done)
    assert agent.poll()[1]["commands"] == []


def test_a_stored_request_tampered_with_after_storage_is_refused(stand):
    """AC-B04: application code verifies every stored request again. A body changed after it was
    stored, one re-hashed to match, and one whose timestamp is far from the time Postgres
    received it are each refused, and none moves the report sequence."""
    agent = stand.agent
    enrolled(stand)
    for sequence in (1, 2, 3):
        assert agent.send("POST", "/agent/v1/report", {"sequence": sequence, "config_sequence": 1, "roots": []})[0] == 202
    forged = json.dumps({"sequence": 99, "config_sequence": 1, "roots": []}).encode()
    with stand.factory.begin() as db:
        first, second, third = db.scalars(select(AgentRequest).where(AgentRequest.route == "report")
                                          .order_by(AgentRequest.timestamp, AgentRequest.id)).all()
        first.body = forged
        second.body, second.content_sha256 = forged, hashlib.sha256(forged).hexdigest()
        third.received_at = now() + timedelta(minutes=10)
    process(stand)
    assert sorted(outcome["reason"] for outcome in outcomes(stand) if outcome["status"] == "refused") == [
        "bad_signature", "body_hash_mismatch", "clock_skew"]
    assert shown(stand)["report_sequence"] == 0


def test_the_listener_refuses_a_bad_signature_a_skewed_clock_and_a_reused_nonce(stand):
    """AC-B04: each is refused and changes nothing: nothing is stored for application code."""
    agent = stand.agent
    enrolled(stand)
    stored = count(stand, AgentRequest)
    nonce = secrets.token_hex(16)
    assert agent.poll(nonce=nonce)[0] == 200
    refusals = [
        (agent.poll(nonce=nonce), (401, {"error": "nonce_reused"})),
        (agent.poll(seed=secrets.token_bytes(32)), (401, {"error": "bad_signature"})),
        (agent.poll(timestamp=int(time.time()) - 301), (401, {"error": "clock_skew"})),
        (agent.poll(digest="0" * 64), (400, {"error": "bad_request"})),
        (agent.poll(agent_id="nobody"), (401, {"error": "unknown_agent"})),
        (agent.poll(agent_id="bad id"), (400, {"error": "bad_request"})),
        (agent.send("POST", "/agent/v1/report", {"sequence": 1, "roots": [{"root": "/var/www/html", "entries": [
            {"path": "../etc/passwd", "type": "file"}]}]}), (400, {"error": "bad_request"})),
        (agent.send("POST", "/agent/v1/upload", {"report_sequence": 1, "complete": True, "files": [
            {"sha256": "0" * 64, "content_b64": base64.b64encode(b"x").decode()}]}), (422, {"error": "hash_mismatch"})),
        (agent.send("POST", "/agent/v1/report", b"[1]"), (400, {"error": "bad_request"})),
    ]
    for got, expected in refusals:
        assert got == expected
    assert count(stand, AgentRequest) == stored + 1


def test_a_revoked_agent_is_refused_and_its_pending_commands_cancelled(stand):
    """AC-B04: after Revoke the agent's next request is refused, a request stored before it starts
    nothing, and its pending commands are cancelled. Its history is kept."""
    agent = stand.agent
    enrolled(stand)
    command = stand.client.post(f"/api/agents/{agent.agent_id}/rescans").json()
    assert agent.send("POST", "/agent/v1/report", {"sequence": 1, "config_sequence": 1, "roots": []})[0] == 202
    revoked = stand.client.post(f"/api/agents/{agent.agent_id}/revocations")
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    stored = count(stand, AgentRequest)
    assert agent.poll() == (403, {"error": "revoked"})
    assert count(stand, AgentRequest) == stored
    process(stand)
    assert {"status": "refused", "reason": "revoked"} in outcomes(stand)
    row = shown(stand)
    assert row["report_sequence"] == 0 and row["fingerprint"]
    assert [(listed["id"], listed["status"]) for listed in row["commands"]] == [(command["id"], "cancelled")]
    assert stand.client.post(f"/api/agents/{agent.agent_id}/rescans").status_code == 409


def test_commands_expire_and_old_processed_requests_are_pruned(stand):
    """A pending command past its expiry is expired; processed requests leave after an hour."""
    agent = stand.agent
    enrolled(stand)
    command = stand.client.post(f"/api/agents/{agent.agent_id}/rescans").json()
    with stand.factory.begin() as db:
        db.execute(update(AgentMessage).where(AgentMessage.id == command["id"])
                   .values(expires_at=now() - timedelta(seconds=1)))
        db.execute(update(AgentRequest).values(received_at=now() - timedelta(hours=2)))
    assert agent.poll()[1]["commands"] == []
    process(stand)
    assert shown(stand)["commands"][0]["status"] == "expired"
    with stand.factory() as db:
        assert [row.route for row in db.scalars(select(AgentRequest))] == ["poll"]
        assert db.get(Agent, agent.agent_id).status == "enrolled"


def test_a_request_that_breaks_its_handler_is_refused_and_the_rest_go_on(stand, monkeypatch):
    """A stored request that raises in its handler, or carries a sequence past the Integer column, is
    refused; it never stops the scheduler's pass, and the next request is still processed."""
    agent = stand.agent
    enrolled(stand)
    assert agent.send("POST", "/agent/v1/report", {"sequence": 2**40, "config_sequence": 1, "roots": []})[0] == 202
    process(stand)
    assert {"status": "refused", "reason": "report_sequence_not_increasing"} in outcomes(stand)

    def broken(*args):
        raise RuntimeError("secret detail")

    with monkeypatch.context() as patch:
        patch.setitem(servers.HANDLERS, "upload", broken)
        assert agent.send("POST", "/agent/v1/upload", {"report_sequence": 1, "files": [], "complete": True})[0] == 202
        process(stand)
    assert agent.send("POST", "/agent/v1/report", {"sequence": 1, "config_sequence": 1, "roots": []})[0] == 202
    process(stand)
    assert {"status": "refused", "reason": "processing_error"} in outcomes(stand)
    assert shown(stand)["report_sequence"] == 1
