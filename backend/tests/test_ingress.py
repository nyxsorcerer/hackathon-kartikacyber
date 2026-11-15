import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from numen import ingress
from numen.models import Base, PushDelivery, PushWebhook, Repository
from numen.security import SECURITY_HEADERS, Vault

NOT_FOUND = {"code": "not_found", "message": "Not found", "retryable": False}
TOO_LARGE = {"code": "request_too_large", "message": "Request body exceeds this route's limit",
             "retryable": False}
RATE_LIMITED = {"code": "rate_limited", "message": "Too many requests; wait before trying again",
                "retryable": True}
WRONG_SIGNATURE = {"code": "signature_invalid",
                   "message": "X-Hub-Signature-256 does not match the body", "retryable": False}
WRONG_EVENT = {"code": "event_not_accepted", "message": "Only push and ping events are accepted",
               "retryable": False}
NO_DELIVERY = {"code": "delivery_id_required", "message": "X-GitHub-Delivery is required",
               "retryable": False}
# The agent listener answers as agent/PROTOCOL.md says: {"error": code}.
AGENT_NOT_FOUND, AGENT_TOO_LARGE = {"error": "not_found"}, {"error": "request_too_large"}
CAP = ingress.BODY_CAP
VAULT = Vault(Fernet.generate_key().decode())


def database():
    """An empty database: one in-memory sqlite connection that every thread shares."""
    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def push_app(factory=None):
    """A push listener; with no factory, on an empty database."""
    return ingress.push_app(factory or database(), VAULT)


def agent_app(factory=None):
    """An agent listener; with no factory, on an empty database."""
    return ingress.agent_app(factory or database())


def webhook(factory):
    """A Push webhook on a new Own repository, stored as Set up stores it; (push id, secret)."""
    push_id, secret = secrets.token_hex(16), secrets.token_hex(32)
    with factory.begin() as db:
        repository = Repository(source_kind="github", source_url=f"https://github.com/acme/{push_id}")
        db.add(repository)
        db.flush()
        db.add(PushWebhook(repository_id=repository.id, push_id=push_id,
                           secret=VAULT.encrypt(secret)))
    return push_id, secret


def signed(secret, body):
    """X-Hub-Signature-256 as GitHub computes it over the raw body."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(client, push_id, secret, body=b'{"zen": "Design for failure."}', event="push",
            delivery=None, signature=None):
    """A Push delivery as GitHub sends it, signed with `secret` unless `signature` is given."""
    headers = {"X-GitHub-Event": event, "X-GitHub-Delivery": delivery or str(uuid.uuid4()),
               "X-Hub-Signature-256": signature or signed(secret, body)}
    return client.post(f"/push/{push_id}", content=body, headers=headers)


def state(factory, push_id):
    """The Push webhook's last accepted and last refusal, and its deliveries as
    (delivery id, body SHA-256)."""
    with factory() as db:
        row = db.scalar(select(PushWebhook).where(PushWebhook.push_id == push_id))
        deliveries = db.execute(select(PushDelivery.delivery_id, PushDelivery.body_sha256)
                                .where(PushDelivery.push_webhook_id == row.id)).all()
        return row.last_accepted, row.last_refusal, deliveries


def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ingress, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return now


def call(app, method, path, headers=(), messages=None):
    """Drives `app` as uvicorn would. `messages` are what receive() returns, in order; with
    None, awaiting receive() fails the test. The status, the JSON body and the unread messages."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": list(headers), "client": ("203.0.113.9", 40000),
             "server": ("testserver", 8084)}
    pending, sent = list(messages or ()), []

    async def receive():
        assert messages is not None, "the listener read a body it had to refuse unread"
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], json.loads(sent[1]["body"]), pending


def tls_key(curve=ec.SECP256R1()):
    """A private key as make init writes NUMEN_AGENT_TLS_KEY: standard base64 of DER PKCS#8."""
    private = ec.generate_private_key(curve)
    der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return private, base64.b64encode(der).decode()


def spki(public):
    return public.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)


def every_kind_of_response(**request):
    """A 200, a 404 and a 413 from the agent listener, and a 404, a 429, a 200 and a 401 from
    the push listener, each from a fresh app, as (status, body, headers without date)."""
    cases = [(agent_app, "GET", "/health", b""),
             (agent_app, "GET", "/api/auth/session", b""),
             (agent_app, "POST", "/health", b"x" * (CAP + 1)),
             (push_app, "POST", "/push/x", b"{}")]
    responses = [TestClient(app()).request(method, path, content=body, **request)
                 for app, method, path, body in cases]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ingress, "PUSH_LISTENER_PER_MINUTE", 0)
        responses.append(TestClient(push_app()).post("/push/x", content=b"{}", **request))
    for secret in (None, "wrong"):
        factory = database()
        push_id, real = webhook(factory)
        app = push_app(factory)
        app.refresh()
        headers = {"X-GitHub-Event": "push", "X-GitHub-Delivery": "d-1",
                   "X-Hub-Signature-256": signed(secret or real, b"{}"),
                   **request.get("headers", {})}
        responses.append(TestClient(app).post(f"/push/{push_id}", content=b"{}", headers=headers))
    assert [response.status_code for response in responses] == [200, 404, 413, 404, 429, 200, 401]
    return [(response.status_code, response.content,
             [item for item in response.headers.multi_items() if item[0] != "date"])
            for response in responses]


def test_neither_listener_serves_the_dashboard():
    """AC-B01: neither listener serves /api, /api/auth/login, the SPA or /assets. The push
    listener answers nothing but POST /push/<push id>, and the agent listener nothing but
    GET /health and the /agent/v1 routes (test_server_agents.py). A wrong method gets 404, never
    405, also on a known push id."""
    dashboard = [("GET", "/"), ("GET", "/index.html"), ("GET", "/assets/index.js"),
                 ("GET", "/api/health"), ("GET", "/api/auth/session"),
                 ("GET", "/api/applications"), ("POST", "/api/auth/login")]
    factory = database()
    known, _ = webhook(factory)
    push_listener = push_app(factory)
    push_listener.refresh()
    for app, not_found in ((push_listener, NOT_FOUND), (agent_app(), AGENT_NOT_FOUND)):
        client = TestClient(app)
        for method, path in dashboard:
            response = client.request(method, path, json={"password": "x" * 12})
            assert (response.status_code, response.json()) == (404, not_found), (method, path)
    push = TestClient(push_listener)
    requests = [*(("POST", f"/push/{secrets.token_hex(16)}"), ("POST", f"/push/{known}/"),
                  ("POST", f"/push/{known.upper()}")),
                *((method, f"/push/{known}") for method in ("GET", "PUT", "DELETE"))]
    for method, path in requests:
        response = push.request(method, path)
        assert (response.status_code, response.json()) == (404, NOT_FOUND), (method, path)
    assert state(factory, known) == (None, None, [])
    agent = TestClient(agent_app())
    response = agent.post("/health")
    assert (response.status_code, response.json()) == (404, AGENT_NOT_FOUND)
    assert agent.head("/health").status_code == 404
    assert agent.get("/health/").status_code == 404
    response = agent.get("/health")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_importing_the_ingress_never_imports_the_dashboard():
    """AC-B01: importing numen.ingress, building both apps and refreshing the known push ids
    loads neither numen.api nor numen.domain, numen.workflows or numen.worker. Alerts, jobs and
    Findings are made only there, so no request to the ingress can send an Alert by itself.
    conftest imports numen.api, so this runs in a fresh interpreter."""
    code = ("import sys, sqlalchemy, sqlalchemy.orm, numen.ingress as ingress; "
            "from numen.models import Base; from numen.security import Vault; "
            "engine = sqlalchemy.create_engine('sqlite://'); Base.metadata.create_all(engine); "
            "ingress.push_app(sqlalchemy.orm.sessionmaker(engine), Vault('')).refresh(); "
            "ingress.agent_app(sqlalchemy.orm.sessionmaker(engine)); "
            "print(sorted(name for name in ('numen.api', 'numen.domain', 'numen.workflows', "
            "'numen.worker') if name in sys.modules))")
    result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parents[1],
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "[]"


def test_the_agent_listener_caps_bodies_on_the_bytes_read():
    """AC-B01: a body over 64 KiB gets 413 request_too_large before anything parses it, also
    when it is sent chunked. A Content-Length over the cap is refused before a byte is read."""
    client = TestClient(agent_app())
    response = client.request("GET", "/health", content=b"x" * CAP)
    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    response = client.request("GET", "/health", content=b"x" * (CAP + 1))
    assert (response.status_code, response.json()) == (413, AGENT_TOO_LARGE)
    chunked = client.build_request("GET", "/health", content=iter([b"x" * (CAP + 1)]))
    assert "content-length" not in chunked.headers
    assert chunked.headers["transfer-encoding"] == "chunked"
    response = client.send(chunked)
    assert (response.status_code, response.json()) == (413, AGENT_TOO_LARGE)

    app = agent_app()
    for length in (str(CAP + 1).encode(), b"10" * 20, b"-1", b"", b"64k"):
        status, body, _ = call(app, "GET", "/health", [(b"content-length", length)])
        assert (status, body) == (413, AGENT_TOO_LARGE), length
    chunk = {"type": "http.request", "body": b"x" * (30 * 1024), "more_body": True}
    assert call(app, "GET", "/health", messages=[chunk] * 4) == (413, AGENT_TOO_LARGE, [chunk])
    done = {"type": "http.request", "body": b"", "more_body": False}
    assert call(app, "GET", "/health", messages=[chunk, chunk, done]) == (
        200, {"status": "ok"}, [])
    assert call(app, "GET", "/health", [(b"content-length", b"61440")],
                [chunk, chunk, done])[:2] == (200, {"status": "ok"})
    assert call(app, "GET", "/health", messages=[chunk])[:2] == (413, AGENT_TOO_LARGE)  # disconnect


def test_an_unknown_push_id_gets_404_and_no_query():
    """AC-B01, B02: the push id's format and the in-memory set of known push ids are checked
    before the body is read, so a request to an unknown push id, well-formed or not, gets 404,
    makes no database query and is recorded nowhere. The listener is registered on Engine
    itself, so it hears every engine."""
    factory = database()
    known, secret = webhook(factory)
    app = push_app(factory)
    statements = []

    def record(connection, cursor, statement, *args):
        statements.append(statement)

    event.listen(Engine, "before_cursor_execute", record)
    try:
        app.refresh()
        assert len(statements) == 1 and "push_webhooks" in statements[0]
        statements.clear()
        client = TestClient(app)
        body = b'{"zen": "Keep it logically awesome."}'
        responses = [deliver(client, path, secret, body)
                     for path in (secrets.token_hex(16), "not a push id!", known[:-1])]
        headers = [(b"x-github-event", b"push"), (b"x-github-delivery", b"d-1"),
                   (b"x-hub-signature-256", signed(secret, body).encode())]
        unread = call(app, "POST", f"/push/{secrets.token_hex(16)}", headers)  # receive() fails
    finally:
        event.remove(Engine, "before_cursor_execute", record)
    assert [(response.status_code, response.json()) for response in responses] == [
        (404, NOT_FOUND)] * 3
    assert unread[:2] == (404, NOT_FOUND)
    assert statements == []
    assert state(factory, known) == (None, None, [])


def test_a_new_push_id_is_accepted_after_the_next_refresh():
    """B02: the push listener accepts a new push id once refresh() (every 15 s in main) has
    loaded it; until then it is unknown and gets 404."""
    factory = database()
    app = push_app(factory)
    app.refresh()
    push_id, secret = webhook(factory)
    client = TestClient(app)
    response = deliver(client, push_id, secret)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)
    app.refresh()
    response = deliver(client, push_id, secret)
    assert (response.status_code, response.json()) == (200, {"status": "accepted"})
    assert ingress.REFRESH_SECONDS == 15


def test_a_valid_push_is_recorded_once_per_delivery_id_and_once_per_body():
    """AC-B02, decision 15: a valid push is recorded once per delivery id, and once per body
    SHA-256. A redelivery (same delivery id) and a replay (same body, new delivery id) get 200
    and change nothing, last accepted included."""
    factory = database()
    push_id, secret = webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    body = b'{"ref": "refs/heads/main", "after": "1111111111111111111111111111111111111111"}'
    first = deliver(client, push_id, secret, body, delivery="d-1")
    assert (first.status_code, first.json()) == (200, {"status": "accepted"})
    accepted, refusal, deliveries = state(factory, push_id)
    assert accepted == {"at": accepted["at"], "event": "push", "delivery_id": "d-1"}
    assert datetime.fromisoformat(accepted["at"]).tzinfo is not None
    assert (refusal, deliveries) == (None, [("d-1", hashlib.sha256(body).hexdigest())])
    for delivery, again in (("d-1", body), ("d-2", body), ("d-1", b'{"another": "body"}')):
        response = deliver(client, push_id, secret, again, delivery=delivery)
        assert (response.status_code, response.json()) == (200, {"status": "duplicate"}), delivery
    assert state(factory, push_id) == (accepted, None, deliveries)
    other = deliver(client, push_id, secret, b'{"another": "body"}', delivery="d-3")
    assert (other.status_code, other.json()) == (200, {"status": "accepted"})
    assert len(state(factory, push_id)[2]) == 2
    assert state(factory, push_id)[0]["delivery_id"] == "d-3"


def test_a_wrong_signature_or_event_changes_nothing_and_shows_why(monkeypatch):
    """AC-B02: a delivery with a wrong signature, another event type or no delivery id records
    no delivery and changes nothing but the repository's last refusal, which shows why. A valid
    ping is recorded as "ping received" and does nothing else (decision 14)."""
    now = clock(monkeypatch)
    factory = database()
    push_id, secret = webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    body = b'{"zen": "Approachable is better than simple."}'
    cases = [
        (dict(signature=signed("not-the-secret", body)), 401, WRONG_SIGNATURE, "wrong_signature"),
        (dict(signature=signed(secret, body + b" ")), 401, WRONG_SIGNATURE, "wrong_signature"),
        (dict(signature=signed(secret, body).removeprefix("sha256=")), 401, WRONG_SIGNATURE,
         "wrong_signature"),
        (dict(signature="sha1=" + signed(secret, body)[7:]), 401, WRONG_SIGNATURE,
         "wrong_signature"),
        (dict(event="issues"), 400, WRONG_EVENT, "event_not_accepted"),
        (dict(event="PUSH"), 400, WRONG_EVENT, "event_not_accepted"),
        (dict(delivery="not a delivery id"), 400, NO_DELIVERY, "delivery_id_missing"),
        (dict(delivery="d" * 65), 400, NO_DELIVERY, "delivery_id_missing"),
    ]
    for change, status, answer, reason in cases:
        now[0] += 60
        response = deliver(client, push_id, secret, body, **change)
        assert (response.status_code, response.json()) == (status, answer), change
        accepted, refusal, deliveries = state(factory, push_id)
        assert (accepted, deliveries) == (None, []), change
        assert refusal == {"at": refusal["at"], "reason": reason}, change
    now[0] += 60
    for missing in ("X-GitHub-Event", "X-GitHub-Delivery", "X-Hub-Signature-256"):
        headers = {"X-GitHub-Event": "push", "X-GitHub-Delivery": "d-9",
                   "X-Hub-Signature-256": signed(secret, body)}
        del headers[missing]
        response = client.post(f"/push/{push_id}", content=body, headers=headers)
        assert response.status_code in (400, 401), missing
    assert state(factory, push_id)[::2] == (None, [])

    refusal = state(factory, push_id)[1]
    ping = deliver(client, push_id, secret, b'{"zen": "Speak like a human.", "hook_id": 1}',
                   event="ping", delivery="p-1")
    assert (ping.status_code, ping.json()) == (200, {"status": "ping received"})
    accepted, after, deliveries = state(factory, push_id)
    assert accepted == {"at": accepted["at"], "event": "ping", "delivery_id": "p-1"}
    assert (after, deliveries) == (refusal, [])


def test_refusals_are_recorded_at_most_once_a_minute_per_push_id(monkeypatch):
    """Decision 15: a refusal reason is recorded at most once a minute per push id, so a flood
    of refused deliveries writes once a minute. Another push id is recorded on its own."""
    now = clock(monkeypatch)
    factory = database()
    (first, secret), (second, _) = webhook(factory), webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    writes = []
    event.listen(factory.kw["bind"], "before_cursor_execute",
                 lambda connection, cursor, statement, *args: writes.append(statement)
                 if statement.startswith("UPDATE") else None)
    assert deliver(client, first, secret, event="issues").status_code == 400
    recorded = state(factory, first)[1]
    assert recorded["reason"] == "event_not_accepted"
    now[0] += 30
    for _ in range(5):
        assert deliver(client, first, secret, signature="sha256=0").status_code == 401
    assert state(factory, first)[1] == recorded
    assert deliver(client, second, secret, event="issues").status_code == 400
    assert state(factory, second)[1]["reason"] == "event_not_accepted"
    assert len(writes) == 2
    now[0] += 30
    assert deliver(client, first, secret, signature="sha256=0").status_code == 401
    assert state(factory, first)[1]["reason"] == "wrong_signature"
    assert len(writes) == 3


def test_each_push_id_has_its_own_bucket(monkeypatch):
    """Decision 15: at most 60 deliveries a minute per push id. The 61st gets 429 and is
    recorded as rate limited; another push id is unaffected."""
    now = clock(monkeypatch)
    factory = database()
    (busy, secret), (quiet, other) = webhook(factory), webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    statuses = {deliver(client, busy, secret, b'{"n": %d}' % n).status_code for n in range(60)}
    assert statuses == {200}
    response = deliver(client, busy, secret, b'{"n": 60}')
    assert (response.status_code, response.json()) == (429, RATE_LIMITED)
    assert state(factory, busy)[1]["reason"] == "rate_limited"
    assert len(state(factory, busy)[2]) == 60
    assert deliver(client, quiet, other).status_code == 200
    now[0] += 60
    assert deliver(client, busy, secret, b'{"n": 60}').status_code == 200


def test_a_push_body_is_capped_at_1_mib_on_the_bytes_read(monkeypatch):
    """AC-B01, decision 15: a Push delivery body over 1 MiB gets 413 before it is hashed, also
    when it is sent chunked, and the repository shows body too large."""
    now = clock(monkeypatch)
    factory = database()
    push_id, secret = webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    cap = ingress.PUSH_CAP
    assert cap == 1024 * 1024
    response = deliver(client, push_id, secret, b"x" * cap)
    assert (response.status_code, response.json()) == (200, {"status": "accepted"})
    response = deliver(client, push_id, secret, b"y" * (cap + 1))
    assert (response.status_code, response.json()) == (413, TOO_LARGE)
    assert state(factory, push_id)[1]["reason"] == "body_too_large"
    assert len(state(factory, push_id)[2]) == 1

    body = b"z" * (cap + 1)
    headers = [(b"x-github-event", b"push"), (b"x-github-delivery", b"d-chunked"),
               (b"x-hub-signature-256", signed(secret, body).encode())]
    chunk = {"type": "http.request", "body": body[:600 * 1024], "more_body": True}
    rest = {"type": "http.request", "body": body[600 * 1024:], "more_body": False}
    now[0] += 60
    assert call(app, "POST", f"/push/{push_id}", headers, [chunk, rest, chunk]) == (
        413, TOO_LARGE, [chunk])
    assert call(app, "POST", f"/push/{push_id}",  # refused before the first receive()
                [*headers, (b"content-length", str(cap + 1).encode())])[:2] == (413, TOO_LARGE)
    assert len(state(factory, push_id)[2]) == 1


def test_the_body_is_never_parsed(monkeypatch):
    """AC-B02, decision 14: the push id names the repository, so the body is only hashed and
    signed, never parsed. A validly signed body that is not JSON is accepted, and a payload that
    lists commits writes only its delivery row: commits come from the GitHub API alone."""
    factory = database()
    push_id, secret = webhook(factory)
    app = push_app(factory)
    app.refresh()
    client = TestClient(app)
    parsed, loads = [], json.loads
    monkeypatch.setattr(json, "loads", lambda value, *a, **k: parsed.append(value) or
                        loads(value, *a, **k))
    garbage = b"\xff\xfe not json at all {"
    assert deliver(client, push_id, secret, garbage).json() == {"status": "accepted"}

    def counts():
        with factory() as db:
            return {table.name: db.scalar(select(func.count()).select_from(table))
                    for table in Base.metadata.sorted_tables}

    before = counts()
    sha = "2222222222222222222222222222222222222222"
    payload = json.dumps({"ref": "refs/heads/main", "after": sha, "head_commit": {"id": sha},
                          "commits": [{"id": sha, "message": "Add a backdoor",
                                       "added": ["wp-config.php"]}]}).encode()
    assert deliver(client, push_id, secret, payload).json() == {"status": "accepted"}
    after = counts()
    assert {name for name in after if after[name] != before[name]} == {"push_deliveries"}
    assert after["push_deliveries"] == before["push_deliveries"] + 1 == 2
    assert all(payload not in (value.encode() if isinstance(value, str) else bytes(value))
               and garbage not in (value.encode() if isinstance(value, str) else bytes(value))
               for value in parsed)


def test_turn_off_and_regenerate_are_refused_at_once(system):
    """AC-B02, decision 17: the push listener reads the Push webhook again for every delivery,
    so after Regenerate the old secret is refused, and after Turn off the push id gets 404 and
    is recorded nowhere, both before the next refresh."""
    app, dashboard, _ = system
    ident = dashboard.post("/api/applications", json={
        "asset_name": "Portal", "asset_url": "https://portal.example.com", "product_kind": "CMS",
        "product_name": "Portal", "monitor_interval_seconds": 172800}).json()["id"]
    link = dashboard.post(f"/api/applications/{ident}/repositories", json={
        "role": "own", "source_kind": "github", "source_url": "https://github.com/acme/portal"})
    url = f"/api/applications/{ident}/repositories/{link.json()['repository_id']}/push-webhook"
    shown = dashboard.post(url).json()
    push_id = shown["path"].removeprefix("/push/")
    factory = app.state.factory
    listener = ingress.push_app(factory, Vault(os.environ["NUMEN_INGRESS_KEY"]))
    listener.refresh()
    client = TestClient(listener)
    assert deliver(client, push_id, shown["secret"]).json() == {"status": "accepted"}

    secret = dashboard.post(f"{url}/secret").json()["secret"]
    response = deliver(client, push_id, shown["secret"], b'{"after": "old"}')
    assert (response.status_code, response.json()) == (401, WRONG_SIGNATURE)
    assert deliver(client, push_id, secret, b'{"after": "new"}').json() == {"status": "accepted"}
    accepted, refusal, deliveries = state(factory, push_id)
    assert refusal["reason"] == "wrong_signature" and len(deliveries) == 2

    assert dashboard.delete(url).status_code == 200
    for body in (b'{"after": "off"}', b'{"zen": "ping"}'):
        response = deliver(client, push_id, secret, body)
        assert (response.status_code, response.json()) == (404, NOT_FOUND)
    with factory() as db:
        assert db.scalars(select(PushWebhook)).all() == []
        assert db.scalars(select(PushDelivery)).all() == []


def test_a_failed_refresh_keeps_the_listener_and_logs_only_the_error_class(monkeypatch, caplog):
    """B01: the refresh thread survives a database outage, keeps the push ids it has, and logs
    only the error's class, since a query's error text can hold a push id."""
    calls = []

    def refresh():
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("SELECT push_id FROM push_webhooks", {"p": "a" * 32},
                                   Exception("server closed the connection"))

    def sleep(seconds):
        assert seconds == ingress.REFRESH_SECONDS
        if len(calls) == 2:
            raise SystemExit

    monkeypatch.setattr(ingress, "time", SimpleNamespace(sleep=sleep))
    with caplog.at_level(logging.WARNING), pytest.raises(SystemExit):
        ingress.refreshing(refresh)
    assert len(calls) == 2
    assert [record.getMessage() for record in caplog.records] == [
        "Refreshing the known push ids failed: OperationalError"]


def test_a_session_cookie_changes_nothing():
    """AC-B01: a request that carries a numen_session cookie is treated exactly like one without
    it. No route sets a cookie, and an app inside listener() never sees the Cookie header."""
    plain = every_kind_of_response()
    cookie = every_kind_of_response(headers={"Cookie": "numen_session=s3ss10n; other=1"})
    assert cookie == plain
    assert all(name != "set-cookie" for _, _, headers in plain for name, _ in headers)

    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["headers"])
        await JSONResponse({})(scope, receive, send)

    app = ingress.listener(inner)
    TestClient(app).get("/", headers={"Cookie": "numen_session=s3ss10n"})
    call(app, "GET", "/", [(b"cookie", b"numen_session=a"), (b"Cookie", b"numen_session=b"),
                           (b"x-kept", b"1")])
    assert seen[1] == [(b"x-kept", b"1")]
    assert all(name.lower() != b"cookie" for headers in seen for name, _ in headers)


def test_every_ingress_response_carries_the_dashboard_headers():
    """Plan: the ingress sends the dashboard's CSP, nosniff and no-referrer on every response,
    the 200, 404, 413 and 429 alike."""
    for status, _, headers in every_kind_of_response():
        for name, value in SECURITY_HEADERS.items():
            assert (name.decode(), value.decode()) in headers, (status, name)


def test_buckets_count_each_key_apart(monkeypatch):
    """B01: a bucket is counted per key (an identity or a global name, never a client address)
    over a sliding window. A refused take is not counted, and an emptied key is dropped."""
    now = [1000.0]
    monkeypatch.setattr(ingress, "time", SimpleNamespace(monotonic=lambda: now[0]))
    buckets = ingress.Buckets()
    assert [buckets.take("agent:a", 3) for _ in range(4)] == [True, True, True, False]
    assert buckets.take("agent:b", 3)
    now[0] += 59
    assert not buckets.take("agent:a", 3)
    now[0] += 1
    # The refused takes at 1000 and 1059 were not counted, so all three are free again.
    assert [buckets.take("agent:a", 3) for _ in range(4)] == [True, True, True, False]
    assert buckets.take("code:c", 1, window=3600)
    now[0] += 120
    assert not buckets.take("code:c", 1, window=3600)
    assert set(buckets.taken) == {"code:c"}
    now[0] += 3600
    assert buckets.take("code:c", 1, window=3600)


def test_the_push_listener_has_one_global_bucket(monkeypatch):
    """B01: at most 120 requests a minute on the push listener in all, whatever the path, and
    not per client address: behind a Public tunnel every client shares one."""
    now = [1000.0]
    monkeypatch.setattr(ingress, "time", SimpleNamespace(monotonic=lambda: now[0]))
    app = push_app()
    client = TestClient(app, client=("198.51.100.1", 50000))
    assert {client.post("/push/x").status_code for _ in range(120)} == {404}
    for response in (client.post("/push/x"), client.get("/api/health"),
                     TestClient(app, client=("203.0.113.2", 50001)).post("/push/x")):
        assert (response.status_code, response.json()) == (429, RATE_LIMITED)
    now[0] += 60
    assert client.post("/push/x").status_code == 404


def test_the_agent_listener_certificate_carries_its_key(tmp_path):
    """B01: the agent listener's self-signed certificate, made at start from
    NUMEN_AGENT_TLS_KEY, carries that key's public half, which On-server agents pin."""
    private, key = tls_key()
    keyfile, certfile = ingress.tls_files(key, tmp_path)
    certificate = x509.load_pem_x509_certificate(certfile.read_bytes())
    assert spki(certificate.public_key()) == spki(private.public_key())
    loaded = serialization.load_pem_private_key(keyfile.read_bytes(), None)
    assert spki(loaded.public_key()) == spki(private.public_key())
    assert stat.S_IMODE(keyfile.stat().st_mode) == stat.S_IMODE(certfile.stat().st_mode) == 0o600
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asset-monitor-agent-listener")])
    assert certificate.subject == certificate.issuer == name
    certificate.verify_directly_issued_by(certificate)
    assert isinstance(certificate.signature_hash_algorithm, hashes.SHA256)
    start = certificate.not_valid_before_utc
    assert timedelta(hours=23) < datetime.now(timezone.utc) - start < timedelta(days=1, hours=1)
    assert certificate.not_valid_after_utc - start == timedelta(days=365)
    ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(certfile, keyfile)
    # Every start makes a new certificate, with a random serial, for the same key.
    (tmp_path / "again").mkdir()
    again = x509.load_pem_x509_certificate(ingress.tls_files(key, tmp_path / "again")[1]
                                           .read_bytes())
    assert again.serial_number != certificate.serial_number
    assert spki(again.public_key()) == spki(certificate.public_key())
    (tmp_path / "p384").mkdir()
    with pytest.raises(ValueError):
        ingress.tls_files(tls_key(ec.SECP384R1())[1], tmp_path / "p384")


def test_main_serves_each_listener_without_an_access_log(monkeypatch, tmp_path):
    """B01: an unknown push id is recorded nowhere, so uvicorn's access log is off. The push
    listener serves container port 8083 from NUMEN_DATABASE_URL and NUMEN_INGRESS_KEY, on a pool
    of at most 2 connections (the role's CONNECTION LIMIT is 5) whose error text hides bound
    parameters, with a daemon thread refreshing its known push ids. The agent listener serves
    8084 over TLS from a fresh temporary directory (the service's tmpfs in Compose), on a pool
    of its own built the same way."""
    runs, engines, threads = [], [], []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: runs.append((app, options)))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(ingress, "create_engine", lambda url, **options: engines.append(options)
                        or create_engine(url, **options))
    monkeypatch.setattr(ingress, "threading", SimpleNamespace(
        Thread=lambda **thread: SimpleNamespace(start=lambda: threads.append(thread))))
    url = f"sqlite:///{tmp_path}/push.sqlite"
    factory = sessionmaker(create_engine(url))
    Base.metadata.create_all(factory.kw["bind"])
    push_id, secret = webhook(factory)
    monkeypatch.setenv("NUMEN_DATABASE_URL", url)
    monkeypatch.setenv("NUMEN_INGRESS_KEY", VAULT.key)
    monkeypatch.setenv("NUMEN_AGENT_TLS_KEY", tls_key()[1])
    for listener in ("push", "agent"):
        monkeypatch.setattr(sys, "argv", ["numen.ingress", listener])
        ingress.main()
    (push, push_options), (agent, agent_options) = runs
    common = {"host": "0.0.0.0", "access_log": False, "lifespan": "off", "ws": "none"}
    assert push_options == {**common, "port": 8083}
    # Each listener's own pool, the agent listener's under asset_monitor_agent's limit too.
    assert engines == [{"pool_size": 2, "max_overflow": 0, "pool_pre_ping": True,
                        "hide_parameters": True}] * 2
    assert threads == [{"target": ingress.refreshing, "args": (push.refresh,), "daemon": True}]
    keyfile, certfile = agent_options.pop("ssl_keyfile"), agent_options.pop("ssl_certfile")
    assert agent_options == {**common, "port": 8084}
    assert Path(keyfile).parent == Path(certfile).parent
    assert Path(keyfile).parent.parent == tmp_path
    client = TestClient(push)
    assert deliver(client, push_id, secret).status_code == 404  # until the thread's first refresh
    push.refresh()
    assert deliver(client, push_id, secret).json() == {"status": "accepted"}
    assert client.post("/push/x").status_code == 404
    assert TestClient(agent).get("/health").json() == {"status": "ok"}
