"""The ingress (B01, ADR-0006): the push listener and the agent listener, each run as its own
process with `python -m numen.ingress push|agent`. Neither imports numen.api or touches the
dashboard's sessions, neither reads a Cookie header, and nothing here logs a header or a body.
The push listener only records Push deliveries (B02); the scheduler turns them into checks."""
import argparse
import base64
import collections
import hashlib
import hmac
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

from numen.config import secret_env
from numen.models import PushDelivery, PushWebhook, now, uid
from numen.security import DomainError, SecurityHeaders, Vault

BODY_CAP = 64 * 1024  # B01: every body but a Push delivery, File manifest or upload.
PUSH_CAP = 1024 * 1024  # B01: a Push delivery.
PUSH_LISTENER_PER_MINUTE = 120
PUSH_PER_MINUTE = 60  # per push id
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


def agent_app():
    """The agent listener: only GET /health, with every body capped at BODY_CAP first."""

    async def app(scope, receive, send):
        if await read_body(scope, receive, BODY_CAP) is None:
            response = error("request_too_large", "Request body exceeds this route's limit", 413)
        elif scope["method"] == "GET" and scope["path"] == "/health":
            response = JSONResponse({"status": "ok"})
        else:
            response = not_found()
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

    if arguments.listener == "push":
        # Under the role's CONNECTION LIMIT 5, and no bound parameter (a push id) in error text.
        engine = create_engine(os.environ["NUMEN_DATABASE_URL"], pool_size=2, max_overflow=0,
                               pool_pre_ping=True, hide_parameters=True)
        app = push_app(sessionmaker(engine), Vault(secret_env("NUMEN_INGRESS_KEY")))
        threading.Thread(target=refreshing, args=(app.refresh,), daemon=True).start()
        port, tls = 8083, {}
    else:
        keyfile, certfile = tls_files(secret_env("NUMEN_AGENT_TLS_KEY"), Path(tempfile.mkdtemp()))
        app, port, tls = agent_app(), 8084, {"ssl_keyfile": str(keyfile),
                                             "ssl_certfile": str(certfile)}
    # No access log: it would record push ids, and an unknown one is recorded nowhere (B01).
    uvicorn.run(app, host="0.0.0.0", port=port, access_log=False, lifespan="off", ws="none", **tls)


if __name__ == "__main__":
    main()
