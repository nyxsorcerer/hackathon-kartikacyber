import asyncio
import base64
import json
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from numen import ingress
from numen.security import SECURITY_HEADERS

NOT_FOUND = {"code": "not_found", "message": "Not found", "retryable": False}
TOO_LARGE = {"code": "request_too_large", "message": "Request body exceeds this route's limit",
             "retryable": False}
RATE_LIMITED = {"code": "rate_limited", "message": "Too many requests; wait before trying again",
                "retryable": True}
CAP = ingress.BODY_CAP


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
    """A 200, a 404 and a 413 from the agent listener, and a 404 and a 429 from the push
    listener, each from a fresh app, as (status, body, headers without date)."""
    cases = [(ingress.agent_app, "GET", "/health", b""),
             (ingress.agent_app, "GET", "/api/auth/session", b""),
             (ingress.agent_app, "POST", "/health", b"x" * (CAP + 1)),
             (ingress.push_app, "POST", "/push/x", b"{}")]
    responses = [TestClient(app()).request(method, path, content=body, **request)
                 for app, method, path, body in cases]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ingress, "PUSH_LISTENER_PER_MINUTE", 0)
        responses.append(TestClient(ingress.push_app()).post("/push/x", content=b"{}", **request))
    assert [response.status_code for response in responses] == [200, 404, 413, 404, 429]
    return [(response.status_code, response.content,
             [item for item in response.headers.multi_items() if item[0] != "date"])
            for response in responses]


def test_neither_listener_serves_the_dashboard():
    """AC-B01: neither listener serves /api, /api/auth/login, the SPA or /assets. The push
    listener answers nothing but POST /push/<push id> (and in Phase 12 no push id exists), and
    the agent listener nothing but GET /health. A wrong method gets 404, never 405."""
    dashboard = [("GET", "/"), ("GET", "/index.html"), ("GET", "/assets/index.js"),
                 ("GET", "/api/health"), ("GET", "/api/auth/session"),
                 ("GET", "/api/applications"), ("POST", "/api/auth/login")]
    for app in (ingress.push_app(), ingress.agent_app()):
        client = TestClient(app)
        for method, path in dashboard:
            response = client.request(method, path, json={"password": "x" * 12})
            assert (response.status_code, response.json()) == (404, NOT_FOUND), (method, path)
    push = TestClient(ingress.push_app())
    for method in ("POST", "GET", "PUT", "DELETE"):
        response = push.request(method, f"/push/{secrets.token_hex(16)}")
        assert (response.status_code, response.json()) == (404, NOT_FOUND), method
    agent = TestClient(ingress.agent_app())
    response = agent.post("/health")
    assert (response.status_code, response.json()) == (404, NOT_FOUND)
    assert agent.head("/health").status_code == 404
    assert agent.get("/health/").status_code == 404
    response = agent.get("/health")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_importing_the_ingress_never_imports_the_dashboard():
    """AC-B01: importing numen.ingress, and building both apps, loads neither numen.api nor
    numen.domain, numen.workflows or numen.worker. Alerts, jobs and Findings are made only
    there, so no request to the ingress can send an Alert by itself. conftest imports numen.api,
    so this runs in a fresh interpreter."""
    code = ("import sys, numen.ingress as ingress; ingress.push_app(); ingress.agent_app(); "
            "print(sorted(name for name in ('numen.api', 'numen.domain', 'numen.workflows', "
            "'numen.worker') if name in sys.modules))")
    result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parents[1],
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "[]"


def test_the_agent_listener_caps_bodies_on_the_bytes_read():
    """AC-B01: a body over 64 KiB gets 413 request_too_large before anything parses it, also
    when it is sent chunked. A Content-Length over the cap is refused before a byte is read."""
    client = TestClient(ingress.agent_app())
    response = client.request("GET", "/health", content=b"x" * CAP)
    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    response = client.request("GET", "/health", content=b"x" * (CAP + 1))
    assert (response.status_code, response.json()) == (413, TOO_LARGE)
    chunked = client.build_request("GET", "/health", content=iter([b"x" * (CAP + 1)]))
    assert "content-length" not in chunked.headers
    assert chunked.headers["transfer-encoding"] == "chunked"
    response = client.send(chunked)
    assert (response.status_code, response.json()) == (413, TOO_LARGE)

    app = ingress.agent_app()
    for length in (str(CAP + 1).encode(), b"10" * 20, b"-1", b"", b"64k"):
        status, body, _ = call(app, "GET", "/health", [(b"content-length", length)])
        assert (status, body) == (413, TOO_LARGE), length
    chunk = {"type": "http.request", "body": b"x" * (30 * 1024), "more_body": True}
    assert call(app, "GET", "/health", messages=[chunk] * 4) == (413, TOO_LARGE, [chunk])
    done = {"type": "http.request", "body": b"", "more_body": False}
    assert call(app, "GET", "/health", messages=[chunk, chunk, done]) == (
        200, {"status": "ok"}, [])
    assert call(app, "GET", "/health", [(b"content-length", b"61440")],
                [chunk, chunk, done])[:2] == (200, {"status": "ok"})
    assert call(app, "GET", "/health", messages=[chunk])[:2] == (413, TOO_LARGE)  # disconnect


def test_an_unknown_push_id_gets_404_and_no_query():
    """AC-B01: a request to an unknown push id, well-formed or not, gets 404 and makes no
    database query. The listener is registered on Engine itself, so it hears every engine."""
    statements = []

    def record(connection, cursor, statement, *args):
        statements.append(statement)

    event.listen(Engine, "before_cursor_execute", record)
    try:
        with create_engine("sqlite://").connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        assert statements == ["SELECT 1"]
        statements.clear()
        client = TestClient(ingress.push_app())
        responses = [client.post(f"/push/{path}", json={"zen": "Keep it logically awesome."},
                                 headers={"X-GitHub-Event": "push"})
                     for path in (secrets.token_hex(16), "not a push id!")]
    finally:
        event.remove(Engine, "before_cursor_execute", record)
    assert [(response.status_code, response.json()) for response in responses] == [
        (404, NOT_FOUND)] * 2
    assert statements == []


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
    app = ingress.push_app()
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
    listener serves container port 8083, and the agent listener 8084 over TLS from a fresh
    temporary directory (the service's tmpfs in Compose)."""
    runs = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: runs.append((app, options)))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("NUMEN_AGENT_TLS_KEY", tls_key()[1])
    for listener in ("push", "agent"):
        monkeypatch.setattr(sys, "argv", ["numen.ingress", listener])
        ingress.main()
    (push, push_options), (agent, agent_options) = runs
    common = {"host": "0.0.0.0", "access_log": False, "lifespan": "off", "ws": "none"}
    assert push_options == {**common, "port": 8083}
    keyfile, certfile = agent_options.pop("ssl_keyfile"), agent_options.pop("ssl_certfile")
    assert agent_options == {**common, "port": 8084}
    assert Path(keyfile).parent == Path(certfile).parent
    assert Path(keyfile).parent.parent == tmp_path
    assert TestClient(push).post("/push/x").status_code == 404
    assert TestClient(agent).get("/health").json() == {"status": "ok"}
