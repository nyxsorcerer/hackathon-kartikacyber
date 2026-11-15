"""The ingress (B01, ADR-0006): the push listener and the agent listener, each run as its own
process with `python -m numen.ingress push|agent`. Neither imports numen.api or touches the
dashboard's sessions, neither reads a Cookie header, and nothing here logs a header or a body."""
import argparse
import base64
import collections
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from starlette.responses import JSONResponse

from numen.config import secret_env
from numen.security import DomainError, SecurityHeaders

BODY_CAP = 64 * 1024  # B01: every body but a Push delivery, File manifest or upload.
PUSH_LISTENER_PER_MINUTE = 120


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


def push_app():
    """The push listener: only POST /push/<push id>, behind one global bucket. No push id exists
    yet, so every request gets the same 404 before its body is read."""
    buckets = Buckets()

    async def app(scope, receive, send):
        if not buckets.take("push", PUSH_LISTENER_PER_MINUTE):
            response = error("rate_limited", "Too many requests; wait before trying again", 429,
                             retryable=True)
        else:
            response = not_found()
        await response(scope, receive, send)

    return listener(app)


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
        app, port, tls = push_app(), 8083, {}
    else:
        keyfile, certfile = tls_files(secret_env("NUMEN_AGENT_TLS_KEY"), Path(tempfile.mkdtemp()))
        app, port, tls = agent_app(), 8084, {"ssl_keyfile": str(keyfile),
                                             "ssl_certfile": str(certfile)}
    # No access log: it would record push ids, and an unknown one is recorded nowhere (B01).
    uvicorn.run(app, host="0.0.0.0", port=port, access_log=False, lifespan="off", ws="none", **tls)


if __name__ == "__main__":
    main()
