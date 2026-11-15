"""The ingress (B01, ADR-0006): the push listener and the agent listener, each run as its own
process with `python -m numen.ingress push|agent`. Neither imports numen.api or touches the
dashboard's sessions, neither reads a Cookie header, and nothing here logs a header or a body.
The push listener only records Push deliveries (B02), and the agent listener only On-server agent
requests (B04); the scheduler acts on them."""
import argparse
import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from numen import agent_wire
from numen.config import secret_env
from numen.models import (
    Agent, AgentMessage, AgentRequest, EnrollmentCode, PushDelivery, PushWebhook, now, uid, utc,
)
from numen.security import DomainError, SecurityHeaders, Vault

BODY_CAP = 64 * 1024  # B01: every body but a Push delivery, File manifest or upload.
PUSH_CAP = 1024 * 1024  # B01: a Push delivery.
REPORT_CAP = UPLOAD_CAP = 16 * 1024 * 1024  # B01: a File manifest, and one upload.
PUSH_LISTENER_PER_MINUTE = 120
PUSH_PER_MINUTE = 60  # per push id
AGENT_PER_MINUTE = 600  # per On-server agent
CODE_PER_HOUR = 10  # Enrollment attempts per Enrollment code
UNKNOWN_PER_MINUTE = 60  # in all, naming an unknown agent or Enrollment code
REFRESH_SECONDS = 15
PUSH_PATH = re.compile(r"/push/([0-9a-f]{32})")
DELIVERY_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
log = logging.getLogger(__name__)


class Buckets:
    """Sliding-window rate limits (B01). A key is an identity (a push id, an agent, an Enrollment
    code) or a global name, never a client address: behind a tunnel every client shares one, so
    a per-address count would let anyone lock everyone out (ADR-0006). uvicorn runs one event
    loop, so no lock is needed."""

    def __init__(self):
        self.taken = {}  # key -> deque of the times each counted take leaves its window

    def take(self, key, limit, window=60.0):
        """Counts one request against `key`; False, and nothing counted, when `limit` takes
        already fall within the last `window` seconds."""
        now = time.monotonic()
        # ponytail: sweeps every key per take, O(keys); a deployment has few identities.
        for name, ends in list(self.taken.items()):
            while ends and ends[0] <= now:
                ends.popleft()
            if not ends:
                del self.taken[name]
        if len(self.taken.get(key, ())) >= limit:
            return False
        self.taken.setdefault(key, collections.deque()).append(now + window)
        return True


async def read_body(scope, receive, cap):
    """The request body, or None when it is over `cap` or the client left. A Content-Length that
    is invalid or over the cap is refused before the first receive(), and every chunk is counted
    as it arrives, so a chunked body is capped too (B01)."""
    for name, value in scope["headers"]:
        if name == b"content-length" and (not value.isdigit() or int(value) > cap):
            return None
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return None
        body += message.get("body", b"")
        if len(body) > cap:
            return None
        if not message.get("more_body", False):
            return bytes(body)


def error(code, message, status, retryable=False):
    return JSONResponse(DomainError(code, message, status, retryable=retryable).as_dict(), status)


def not_found():
    return error("not_found", "Not found", 404)


def listener(app):
    """An ingress app as served: HTTP only, with every Cookie header removed before `app` sees
    the request, and the dashboard's security headers on every response."""

    async def without_cookies(scope, receive, send):
        if scope["type"] != "http":
            return
        headers = [(name, value) for name, value in scope["headers"] if name.lower() != b"cookie"]
        await app({**scope, "headers": headers}, receive, send)

    return SecurityHeaders(without_cookies)


def rate_limited():
    return error("rate_limited", "Too many requests; wait before trying again", 429, retryable=True)


def push_app(factory, vault):
    """The push listener (B02): only POST /push/<push id>, behind one global bucket and one per
    push id. A push id is looked up in the in-memory set that the returned app's refresh()
    reloads, so an unknown one gets 404 before its body is read, with no query. A known one's
    row is read again for every delivery, so Turn off and Regenerate apply at once. The body is
    only hashed and checked against X-Hub-Signature-256, never parsed. Bucket takes stay on the
    event loop; only database work runs in the thread pool."""
    buckets, known = Buckets(), frozenset()

    def refresh():
        nonlocal known
        with factory() as db:
            known = frozenset(db.scalars(select(PushWebhook.push_id)))

    def record(push_id, **values):
        with factory.begin() as db:
            db.execute(update(PushWebhook).where(PushWebhook.push_id == push_id).values(**values))

    def receive_delivery(push_id, event, delivery_id, body, signature):
        """None when the push id is gone; else wrong_signature, duplicate, accepted or ping
        received."""
        with factory.begin() as db:
            webhook = db.execute(select(PushWebhook.id, PushWebhook.secret)
                                 .where(PushWebhook.push_id == push_id)).one_or_none()
            if webhook is None:
                return None
            key = vault.decrypt(webhook.secret).encode()
            expected = b"sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest().encode()
            if not hmac.compare_digest(expected, signature):
                return "wrong_signature"
            if event == "push":
                # A redelivery or a replayed body hits a unique key. No RETURNING: the push role
                # may insert into push_deliveries but not read it (ADR-0006).
                try:
                    with db.begin_nested():
                        db.execute(insert(PushDelivery).values(
                            id=uid(), push_webhook_id=webhook.id, delivery_id=delivery_id,
                            body_sha256=hashlib.sha256(body).hexdigest(), received_at=now()))
                except IntegrityError:
                    return "duplicate"
            db.execute(update(PushWebhook).where(PushWebhook.push_id == push_id).values(
                last_accepted={"at": now().isoformat(), "event": event, "delivery_id": delivery_id}))
            return "accepted" if event == "push" else "ping received"

    async def refused(push_id, reason, response):
        """The repository shows the reason, recorded at most once a minute per push id."""
        if buckets.take(("refusal", push_id), 1):
            await run_in_threadpool(record, push_id,
                                    last_refusal={"at": now().isoformat(), "reason": reason})
        return response

    async def answer(scope, receive):
        if not buckets.take("push", PUSH_LISTENER_PER_MINUTE):
            return rate_limited()
        match = PUSH_PATH.fullmatch(scope["path"])
        if scope["method"] != "POST" or not match or match[1] not in known:
            return not_found()
        push_id, headers = match[1], dict(scope["headers"])
        event = headers.get(b"x-github-event")
        delivery_id = headers.get(b"x-github-delivery", b"").decode("latin-1")
        if not buckets.take(("push", push_id), PUSH_PER_MINUTE):
            return await refused(push_id, "rate_limited", rate_limited())
        if event not in (b"push", b"ping"):
            return await refused(push_id, "event_not_accepted", error(
                "event_not_accepted", "Only push and ping events are accepted", 400))
        if not DELIVERY_ID.fullmatch(delivery_id):
            return await refused(push_id, "delivery_id_missing", error(
                "delivery_id_required", "X-GitHub-Delivery is required", 400))
        body = await read_body(scope, receive, PUSH_CAP)
        if body is None:
            return await refused(push_id, "body_too_large", error(
                "request_too_large", "Request body exceeds this route's limit", 413))
        outcome = await run_in_threadpool(receive_delivery, push_id, event.decode(), delivery_id,
                                          body, headers.get(b"x-hub-signature-256", b""))
        if outcome is None:
            return not_found()
        if outcome == "wrong_signature":
            return await refused(push_id, outcome, error(
                "signature_invalid", "X-Hub-Signature-256 does not match the body", 401))
        return JSONResponse({"status": outcome})

    async def app(scope, receive, send):
        response = await answer(scope, receive)
        await response(scope, receive, send)

    served = listener(app)
    served.refresh = refresh
    return served


def refreshing(refresh):
    """Runs refresh() every REFRESH_SECONDS. A failure, a database outage say, keeps the push ids
    already known and is logged by its class alone: a query's error text can hold a push id."""
    while True:
        try:
            refresh()
        except Exception as exc:
            log.warning("Refreshing the known push ids failed: %s", type(exc).__name__)
        time.sleep(REFRESH_SECONDS)


AGENT_ROUTES = {("POST", "/agent/v1/enroll"): "enroll", ("GET", "/agent/v1/poll"): "poll",
                ("POST", "/agent/v1/report"): "report", ("POST", "/agent/v1/upload"): "upload",
                ("POST", "/agent/v1/result"): "result"}
CAPS = {"report": REPORT_CAP, "upload": UPLOAD_CAP}
TIMESTAMP = re.compile(r"[0-9]{1,12}")
SIGNATURE = re.compile(r"[A-Za-z0-9+/]{86}==")
AGENT_HEADERS = (b"x-agent-id", b"x-agent-timestamp", b"x-agent-nonce", b"x-agent-content-sha256",
                 b"x-agent-signature")


def refused(status, code):
    """An agent listener refusal as agent/PROTOCOL.md has it: {"error": code}."""
    return JSONResponse({"error": code}, status)


def rate_limited_agent():
    return refused(429, "rate_limited")


def envelope(row):
    return {"payload": row.payload, "signature": row.signature, "key_id": row.key_id}


def parsed(body):
    """The body as a JSON object, or None."""
    try:
        document = json.loads(body)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def route_refusal(route, document):
    """B05's listener checks on a report's paths and an upload's bytes: (status, code) or None."""
    try:
        if route == "report":
            for root in document.get("roots") or []:
                if not all(agent_wire.valid_path(entry["path"]) for entry in root["entries"]):
                    return 400, "bad_request"
        elif route == "upload":
            for item in document.get("files") or []:
                content = base64.b64decode(item["content_b64"], validate=True)
                if not agent_wire.SHA256.fullmatch(item["sha256"]) or hashlib.sha256(content).hexdigest() != item["sha256"]:
                    return 422, "hash_mismatch"
    except (KeyError, TypeError, ValueError, AttributeError):
        return 400, "bad_request"
    return None


def agent_app(factory):
    """The agent listener (B01, B04): GET /health and the five /agent/v1 routes of agent/PROTOCOL.md,
    anything else 404. Each request's headers are checked first, then its agent, read by the
    columns the agent role may read, then its body (capped per route), its hash, its signature,
    its timestamp and the route's checks. It is then stored as received, with no RETURNING, and
    its nonce is unique per agent. Application code verifies it again before anything uses it:
    the listener checks no Enrollment code's secret and changes no agent. Buckets count per
    agent, per Enrollment code and, for unknown ones, in all."""
    buckets = Buckets()

    def lookup(agent_id):
        with factory() as db:
            return db.execute(select(Agent.id, Agent.public_key, Agent.status, Agent.wanted)
                              .where(Agent.id == agent_id)).one_or_none()

    def enrollment_code(agent_id, code_id):
        with factory() as db:
            return db.execute(select(EnrollmentCode.id, EnrollmentCode.expires_at, EnrollmentCode.used_at)
                              .where(EnrollmentCode.id == code_id, EnrollmentCode.agent_id == agent_id)
                              ).one_or_none()

    def store(values):
        """False when the agent already sent this nonce."""
        try:
            with factory.begin() as db:
                db.execute(insert(AgentRequest).values(id=uid(), **values))
        except IntegrityError:
            return False
        return True

    def messages(agent_id):
        """The latest configuration and every pending, unexpired command, as envelopes."""
        columns = (AgentMessage.payload, AgentMessage.signature, AgentMessage.key_id)
        mine = AgentMessage.agent_id == agent_id
        with factory() as db:
            configuration = db.execute(select(*columns).where(
                mine, AgentMessage.type == "configuration", AgentMessage.status != "cancelled")
                .order_by(AgentMessage.sequence.desc()).limit(1)).one_or_none()
            commands = db.execute(select(*columns).where(
                mine, AgentMessage.type == "command", AgentMessage.status == "pending",
                AgentMessage.expires_at > now()).order_by(AgentMessage.sequence)).all()
        return (envelope(configuration) if configuration else None), [envelope(row) for row in commands]

    def unknown(code):
        return refused(401, code) if buckets.take("unknown", UNKNOWN_PER_MINUTE) else rate_limited_agent()

    async def answer(scope, receive):
        route = AGENT_ROUTES.get((scope["method"], scope["path"]))
        if route is None:
            if await read_body(scope, receive, BODY_CAP) is None:
                return refused(413, "request_too_large")
            if scope["method"] == "GET" and scope["path"] == "/health":
                return JSONResponse({"status": "ok"})
            return refused(404, "not_found")
        headers = dict(scope["headers"])
        agent_id, timestamp, nonce, digest, signature = (
            headers.get(name, b"").decode("latin-1") for name in AGENT_HEADERS)
        if not (agent_wire.ID.fullmatch(agent_id) and TIMESTAMP.fullmatch(timestamp)
                and agent_wire.NONCE.fullmatch(nonce) and agent_wire.SHA256.fullmatch(digest)
                and SIGNATURE.fullmatch(signature)):
            return refused(400, "bad_request")
        agent = await run_in_threadpool(lookup, agent_id)
        if agent is None or (route != "enroll" and not agent.public_key):
            return unknown("unknown_agent")
        if not buckets.take(("agent", agent_id), AGENT_PER_MINUTE):
            return rate_limited_agent()
        if agent.status == "revoked":
            return refused(403, "revoked")
        body = await read_body(scope, receive, CAPS.get(route, BODY_CAP))
        if body is None:
            return refused(413, "request_too_large")
        if hashlib.sha256(body).hexdigest() != digest:
            return refused(400, "bad_request")
        document = None if route == "poll" else await run_in_threadpool(parsed, body)
        if route != "poll" and document is None:
            return refused(400, "bad_request")
        key = document.get("public_key") if route == "enroll" else agent.public_key
        signed = agent_wire.signed_bytes(scope["method"], agent_wire.target(scope), timestamp, nonce, digest)
        if not agent_wire.verify(key, signature, signed):
            return refused(401, "bad_signature")
        if abs(int(timestamp) - time.time()) > agent_wire.WINDOW:
            return refused(401, "clock_skew")
        if route == "enroll":
            code = document.get("enrollment_code")
            code_id = code.partition(".")[0] if isinstance(code, str) else ""
            row = await run_in_threadpool(enrollment_code, agent_id, code_id) if code_id else None
            if row is None:
                return unknown("enrollment_refused")
            if not buckets.take(("code", code_id), CODE_PER_HOUR, window=3600):
                return rate_limited_agent()
            if (document.get("agent_id") != agent_id or agent.status != "awaiting_enrollment"
                    or row.used_at is not None or utc(row.expires_at) <= now()):
                return refused(401, "enrollment_refused")
        if route in CAPS and (problem := await run_in_threadpool(route_refusal, route, document)):
            return refused(*problem)
        stored = await run_in_threadpool(store, {
            "agent_id": agent_id, "route": route, "method": scope["method"], "target": agent_wire.target(scope),
            "timestamp": int(timestamp), "nonce": nonce, "content_sha256": digest, "signature": signature,
            "body": body})
        if not stored:
            return refused(401, "nonce_reused")
        if route == "enroll":
            return JSONResponse({"status": "pending"}, 202)
        if route != "poll":
            return JSONResponse({"status": "accepted"}, 202)
        if agent.status != "enrolled":  # a pending agent gets nothing signed
            return JSONResponse({"configuration": None, "commands": [], "wanted": None})
        configuration, commands = await run_in_threadpool(messages, agent_id)
        return JSONResponse({"configuration": configuration, "commands": commands, "wanted": agent.wanted})

    async def app(scope, receive, send):
        response = await answer(scope, receive)
        await response(scope, receive, send)

    return listener(app)


def tls_files(key, directory):
    """Writes the agent listener's key.pem and a new self-signed cert.pem, both 0600, into
    `directory`, from `key`: a P-256 private key as standard base64 of DER PKCS#8 (make init).
    On-server agents pin the public key, not the certificate, so each start makes a new one."""
    private = serialization.load_der_private_key(base64.b64decode(key, validate=True), None)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or private.curve.name != "secp256r1":
        raise ValueError("NUMEN_AGENT_TLS_KEY is not a P-256 private key")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asset-monitor-agent-listener")])
    start = datetime.now(timezone.utc) - timedelta(days=1)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(private.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(start + timedelta(days=365))
        .sign(private, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    files = {
        directory / "key.pem": private.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        directory / "cert.pem": certificate.public_bytes(pem),
    }
    for path, data in files.items():
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
            file.write(data)
    return tuple(files)


def main():
    parser = argparse.ArgumentParser(description="Serve one ingress listener (B01).")
    parser.add_argument("listener", choices=("push", "agent"))
    arguments = parser.parse_args()
    import uvicorn

    # Under the role's CONNECTION LIMIT 5, and no bound parameter (a push id, a body) in error text.
    engine = create_engine(os.environ["NUMEN_DATABASE_URL"], pool_size=2, max_overflow=0,
                           pool_pre_ping=True, hide_parameters=True)
    if arguments.listener == "push":
        app = push_app(sessionmaker(engine), Vault(secret_env("NUMEN_INGRESS_KEY")))
        threading.Thread(target=refreshing, args=(app.refresh,), daemon=True).start()
        port, tls = 8083, {}
    else:
        keyfile, certfile = tls_files(secret_env("NUMEN_AGENT_TLS_KEY"), Path(tempfile.mkdtemp()))
        app, port, tls = agent_app(sessionmaker(engine)), 8084, {"ssl_keyfile": str(keyfile),
                                                                 "ssl_certfile": str(certfile)}
    # No access log: it would record push ids, and an unknown one is recorded nowhere (B01).
    uvicorn.run(app, host="0.0.0.0", port=port, access_log=False, lifespan="off", ws="none", **tls)


if __name__ == "__main__":
    main()
