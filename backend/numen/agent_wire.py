"""The On-server agent's wire protocol (agent/PROTOCOL.md, B04): the request signing string, the
Dashboard-signed envelope and the manifest path rule. Pure, on the stdlib and cryptography only, so
the agent listener and application code check requests the same way."""
import base64
import fnmatch
import hashlib
import posixpath
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REQUEST_PREFIX = b"asset-monitor-agent-request-v1"
MESSAGE_PREFIX = b"asset-monitor-dashboard-message-v1\n"
ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
NONCE = re.compile(r"[0-9a-f]{32}")
SHA256 = re.compile(r"[0-9a-f]{64}")
WINDOW = 300  # seconds a request's timestamp may be off, and a nonce stays unique
MAX_PATH = 4096
# B05's secret list, ported from agent/files.go isSecret: never asked for, only hashed. Case is ignored.
SECRET_DIRS = frozenset((".ssh", ".gnupg", ".aws", ".composer", ".config", ".git"))
SECRET_NAMES = frozenset(("authorized_keys", ".htpasswd", "auth.json", ".git-credentials", ".netrc", ".my.cnf",
                          ".pgpass", ".npmrc", "configuration.php", "localsettings.php"))
SECRET_GLOBS = (".env*", "wp-config*", "*_history", "*.sql*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.kdbx",
                "*.sqlite", "*.db")
# Asked for first in a wanted list (B05).
WEB_EXECUTABLE = (".php", ".phtml", ".phar", ".htaccess", ".user.ini", ".js")


def b64(value, size):
    """Strict standard base64 of exactly `size` bytes; ValueError otherwise."""
    raw = base64.b64decode(value, validate=True)
    if len(raw) != size:
        raise ValueError("wrong length")
    return raw


def signed_bytes(method, target, timestamp, nonce, body_sha256):
    """The bytes the Agent key signs: six fields joined by \\n, with no trailing newline. `target`
    is the raw path and query, latin-1 as in target()."""
    fields = (method, target, str(timestamp), nonce, body_sha256)
    return b"\n".join([REQUEST_PREFIX, *(field.encode("latin-1") for field in fields)])


def target(scope):
    """The request target exactly as sent: the raw path, then ? and the raw query string if any."""
    path = (scope.get("raw_path") or scope["path"].encode()).decode("latin-1")
    query = scope.get("query_string") or b""
    return path + ("?" + query.decode("latin-1") if query else "")


def verify(public_key_b64, signature_b64, data):
    """True only when the signature verifies; never raises, whatever the inputs are."""
    try:
        Ed25519PublicKey.from_public_bytes(b64(public_key_b64, 32)).verify(b64(signature_b64, 64), data)
        return True
    except Exception:
        return False


def fingerprint(public_key_b64):
    """sha256:<hex of the raw 32-byte public key>, as `enroll` prints it."""
    return "sha256:" + hashlib.sha256(b64(public_key_b64, 32)).hexdigest()


def public_key(seed):
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()).decode()


def envelope(seed, payload, key_id):
    """A Dashboard-signed message: the payload bytes and their signature, both standard base64."""
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(MESSAGE_PREFIX + payload)
    return {"payload": base64.b64encode(payload).decode(), "signature": base64.b64encode(signature).decode(),
            "key_id": key_id}


def valid_path(p):
    """A manifest path as the agent's validRel accepts it: relative, normalized, never . or .., no
    NUL, at most 4,096 bytes."""
    try:
        size = len(p.encode())
    except (AttributeError, UnicodeEncodeError):
        return False
    return (p not in ("", ".", "..") and size <= MAX_PATH and "\0" not in p and not p.startswith("/")
            and posixpath.normpath(p) == p and not p.startswith("../"))


def is_secret(full_path):
    """Whether the bytes at an absolute path are on the secret list (agent/files.go isSecret)."""
    *folders, name = full_path.lower().split("/")
    return (any(folder in SECRET_DIRS for folder in folders) or name in SECRET_NAMES
            or (name.startswith("id_") and not name.endswith(".pub"))
            or any(fnmatch.fnmatchcase(name, glob) for glob in SECRET_GLOBS)
            or (len(folders) >= 2 and folders[-2] == "sites" and name == "settings.php")
            or (len(folders) >= 2 and folders[-2:] == ["app", "etc"] and name == "env.php"))
