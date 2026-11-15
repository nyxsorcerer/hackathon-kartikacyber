"""agent/PROTOCOL.md's test vectors, reproduced with numen.agent_wire, so the dashboard signs and
checks exactly the bytes the Go agent does."""
import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from numen import agent_wire

AGENT_SEED, DASHBOARD_SEED = bytes(range(32)), bytes(range(32, 64))
AGENT_KEY = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
DASHBOARD_KEY = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="
NONCE = "00112233445566778899aabbccddeeff"


def sign(seed, data):
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(seed).sign(data)).decode()


def test_keys_and_fingerprint():
    assert agent_wire.public_key(AGENT_SEED) == AGENT_KEY
    assert agent_wire.public_key(DASHBOARD_SEED) == DASHBOARD_KEY
    assert agent_wire.fingerprint(AGENT_KEY) == (
        "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c")


def test_request_signatures():
    body = b'{"sequence":1}'
    digest = hashlib.sha256(body).hexdigest()
    assert digest == "603ff4b70ceeeda2a87631465b1a7089df62b5d48e4426d1bbe9bd2c219f0bfd"
    report = agent_wire.signed_bytes("POST", "/agent/v1/report", 1763200000, NONCE, digest)
    assert report == (b"asset-monitor-agent-request-v1\nPOST\n/agent/v1/report\n1763200000\n"
                      b"00112233445566778899aabbccddeeff\n" + digest.encode())
    signature = "KDJeQWvVYRHhQWv9RAPqs2gw0KOyJufUrC4zZmTmUhe24yle96ZWuN8sX6cUD+wC9UQqeMlzpfzd65s4ioc1Aw=="
    assert sign(AGENT_SEED, report) == signature
    assert agent_wire.verify(AGENT_KEY, signature, report)
    poll = "/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0"
    assert agent_wire.target({"raw_path": poll.split("?")[0].encode(),
                              "query_string": poll.split("?")[1].encode(), "path": "x"}) == poll
    signed = agent_wire.signed_bytes("GET", poll, 1763200000, NONCE, hashlib.sha256(b"").hexdigest())
    signature = "wZPPf2T6G3h/UKohvxV0EftI5ows1XxjkUKpGvJjcK3JZNyC2L6wNph00YwQGLSltvcSHDWIb2wdGdq1YthNBw=="
    assert sign(AGENT_SEED, signed) == signature
    assert agent_wire.verify(AGENT_KEY, signature, signed)
    # A changed byte, a wrong key or a malformed input is refused, and nothing raises.
    assert not agent_wire.verify(AGENT_KEY, signature, signed + b"x")
    assert not agent_wire.verify(DASHBOARD_KEY, signature, signed)
    for key, sig in ((AGENT_KEY, "not base64!"), ("", signature), (None, None), (AGENT_KEY, signature[:-4])):
        assert not agent_wire.verify(key, sig, signed)


def test_configuration_and_command_envelopes():
    payload = (b'{"v":1,"type":"configuration","agent_id":"agent-1","key_id":"dk-1","sequence":1,'
               b'"issued_at":1763200000,"expires_at":0,"body":{"watched_roots":["/var/www/html"],'
               b'"report_interval_seconds":3600,"poll_interval_seconds":30}}')
    # The dashboard's own serialization gives these very bytes.
    assert json.dumps(json.loads(payload), separators=(",", ":")).encode() == payload
    assert agent_wire.envelope(DASHBOARD_SEED, payload, "dk-1") == {
        "payload": "eyJ2IjoxLCJ0eXBlIjoiY29uZmlndXJhdGlvbiIsImFnZW50X2lkIjoiYWdlbnQtMSIsImtleV9pZCI6ImRrLTEiLCJzZXF1"
                   "ZW5jZSI6MSwiaXNzdWVkX2F0IjoxNzYzMjAwMDAwLCJleHBpcmVzX2F0IjowLCJib2R5Ijp7IndhdGNoZWRfcm9vdHMi"
                   "OlsiL3Zhci93d3cvaHRtbCJdLCJyZXBvcnRfaW50ZXJ2YWxfc2Vjb25kcyI6MzYwMCwicG9sbF9pbnRlcnZhbF9zZWNv"
                   "bmRzIjozMH19",
        "signature": "MX3Av+7cgGwi9rdyvFlxlhA0BK26jLU0GHr2Nx8unhd6Oio6ye5eUHEQzUg8qhdXHoH7Ar9hHvKa7JOhU9FmBA==",
        "key_id": "dk-1",
    }
    command = (b'{"v":1,"type":"command","agent_id":"agent-1","key_id":"dk-1","sequence":2,'
               b'"issued_at":1763200000,"expires_at":1763200900,"body":{"command_id":"cmd-1","name":"rescan"}}')
    signed = agent_wire.envelope(DASHBOARD_SEED, command, "dk-1")
    assert signed["signature"] == (
        "LkOZ3EVu20RTFtqA5OqTyUV4lwnYngVuXbflAsbJFUqAFEk+Y8cnNOStls95eB7Xc+DoILRamQnUtaZt0BDdCg==")
    assert agent_wire.verify(DASHBOARD_KEY, signed["signature"], agent_wire.MESSAGE_PREFIX + command)


def test_valid_path_matches_the_agents_rule():
    for path in ("index.php", "wp-content/x.php", ".env", "a..b", "..a/b", "é.php", "a" * 4096):
        assert agent_wire.valid_path(path), path
    for path in ("", ".", "..", "../x", "/etc/passwd", "a/../b", "a//b", "a/", "./a", "a/.", "a\0b",
                 "a" * 4097, "\ud800", None, 7):
        assert not agent_wire.valid_path(path), path


@pytest.mark.parametrize("path, secret", [
    ("/var/www/html/wp-config.php", True), ("/var/www/html/WP-Config.PHP.bak", True), ("/var/www/html/.env.local", True),
    ("/var/www/html/.git/config", True), ("/home/u/.ssh/known_hosts", True), ("/var/www/html/id_rsa", True),
    ("/var/www/html/id_rsa.pub", False), ("/var/www/html/sites/default/settings.php", True),
    ("/var/www/html/settings.php", False), ("/var/www/html/app/etc/env.php", True), ("/var/www/html/dump.sql.gz", True),
    ("/var/www/html/LocalSettings.php", True), ("/var/www/html/index.php", False),
    ("/var/www/html/wp-content/uploads/cache.php", False),
])
def test_the_secret_list_matches_the_agents(path, secret):
    """B05: agent/files.go isSecret's list, case-insensitive."""
    assert agent_wire.is_secret(path) is secret
