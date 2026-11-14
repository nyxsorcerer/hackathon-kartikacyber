import base64
import hashlib
import hmac
import json
import secrets
import math
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from cryptography.fernet import Fernet, InvalidToken


class DomainError(Exception):
    def __init__(self, code, message, status=400, fields=None, retryable=False):
        self.code, self.message, self.status = code, message, status
        self.fields, self.retryable = fields, retryable

    def as_dict(self):
        result = {"code": self.code, "message": self.message, "retryable": self.retryable}
        if self.fields:
            result["fields"] = self.fields
        return result


def retry_delay(value, fallback, maximum):
    try:
        delay = float(value)
        if not math.isfinite(delay):
            raise ValueError
    except (ValueError, TypeError):
        try:
            date = parsedate_to_datetime(value)
            delay = (date - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError):
            delay = fallback
    return max(0, min(delay, maximum))


def hash_password(password):
    if len(password) < 12:
        raise DomainError("password_too_short", "Password must contain at least 12 characters", 422)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def verify_password(password, encoded):
    try:
        _, rounds, salt, digest = encoded.split("$")
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Vault:
    def __init__(self, key):
        self.key = key
        self.fernet = Fernet(key.encode()) if key else None

    def encrypt(self, obj):
        if not self.fernet:
            raise DomainError(
                "vault_unconfigured",
                "Configure the credential encryption key before saving secrets",
                503,
            )
        return self.fernet.encrypt(json.dumps(obj).encode()).decode()

    def decrypt(self, value):
        if not value:
            return {}
        if not self.fernet:
            raise DomainError("vault_unconfigured", "Credential encryption key is unavailable", 503)
        try:
            return json.loads(self.fernet.decrypt(value.encode()))
        except InvalidToken as exc:
            raise DomainError(
                "vault_key_mismatch", "Cannot decrypt credentials with the configured key", 503
            ) from exc


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()


def decode_content(value):
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise DomainError("invalid_output", "Output is not valid base64", 422) from exc


def normalize_native_cache(provider, value):
    if not isinstance(value, dict):
        raise DomainError(
            "invalid_native_cache", "Native credential cache must be a JSON object", 422
        )
    if provider == "commandcode":
        return normalize_commandcode_cache(value)
    wrapper = "auth_json" if provider == "openai" else "credentials_json"
    cache = value.get(wrapper, value)
    if not isinstance(cache, dict):
        raise DomainError(
            "invalid_native_cache", "Native credential cache has an invalid envelope", 422
        )
    if provider == "openai":
        tokens = cache.get("tokens", {})
        keys = ("access_token", "refresh_token")
        if cache.get("OPENAI_API_KEY") is not None:
            raise DomainError(
                "wrong_auth_mode", "An API-key cache cannot be imported as native OAuth", 422
            )
    elif provider == "claude":
        tokens = cache.get("claudeAiOauth", {})
        keys = ("accessToken", "refreshToken")
    else:
        raise DomainError(
            "unsupported_native_cache", "This provider does not support native cache import", 422
        )
    if not isinstance(tokens, dict) or any(
        not isinstance(tokens.get(key), str) or not tokens[key].strip() for key in keys
    ):
        raise DomainError(
            "invalid_native_cache",
            "Native cache must contain access and refresh token fields for this provider",
            422,
        )
    envelope = {wrapper: cache}
    try:
        size = len(json.dumps(envelope, allow_nan=False).encode())
    except ValueError as exc:
        raise DomainError(
            "invalid_native_cache", "Native cache contains invalid JSON values", 422
        ) from exc
    if size > 256 * 1024:
        raise DomainError(
            "native_cache_too_large",
            "Protected native cache exceeds the runner's 256 KiB limit",
            413,
        )
    return envelope


def normalize_commandcode_cache(value):
    # Accept pi's auth.json (as written by the plugin's /login) or Command Code CLI's
    # ~/.commandcode/auth.json. Both hold the same non-expiring API key.
    cache = value.get("auth_json", value)
    entry = cache.get("commandcode") if isinstance(cache, dict) else None
    if isinstance(entry, dict):
        key = entry.get("access") if entry.get("type") == "oauth" else entry.get("key")
    else:
        key = cache.get("apiKey") if isinstance(cache, dict) else None
    if not isinstance(key, str) or not key.strip() or len(key) > 4096:
        raise DomainError(
            "invalid_native_cache",
            "Native cache must contain a Command Code login from pi or the Command Code CLI",
            422,
        )
    key = key.strip()
    return {"auth_json": {"commandcode": {"type": "oauth", "access": key, "refresh": key}}}


class RequestLimits:
    """Bound request bytes before JSON or multipart parsers allocate/spool the whole body."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PATCH", "PUT"):
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse

        path = scope.get("path", "")
        limit = 1024 * 1024
        if path.endswith("/native-cache"):
            limit += 65536  # Multipart framing plus a bounded 1 MiB credential file.
        elif path.startswith("/api/findings/") and path.endswith("/artifacts"):
            limit = 65 * 1024 * 1024
        headers = dict(scope.get("headers", []))
        try:
            oversized = int(headers.get(b"content-length", b"0")) > limit
        except ValueError:
            oversized = True
        if oversized:
            response = JSONResponse(
                {
                    "code": "request_too_large",
                    "message": "Request body exceeds this operation's limit",
                    "retryable": False,
                },
                status_code=413,
            )
            return await response(scope, receive, send)
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > limit:
                raise DomainError(
                    "request_too_large", "Request body exceeds this operation's limit", 413
                )
            return message

        return await self.app(scope, bounded_receive, send)


# A15: no inline script anywhere; img data: is the select arrow's SVG in styles.css.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
SECURITY_HEADERS = {
    b"content-security-policy": CONTENT_SECURITY_POLICY.encode(),
    b"x-content-type-options": b"nosniff",
    b"referrer-policy": b"no-referrer",
}


class SecurityHeaders:
    """Sets the A15 response headers on every HTTP response, replacing a route's own copy."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secured_send(message):
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in SECURITY_HEADERS
                ]
                message = {**message, "headers": headers + list(SECURITY_HEADERS.items())}
            await send(message)

        return await self.app(scope, receive, secured_send)
