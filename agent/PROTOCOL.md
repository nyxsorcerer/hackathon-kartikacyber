# On-server agent wire protocol, version 1

This is the contract between the Go On-server agent (`agent/`) and the agent listener and application code (Phase 15b and 16a). The Go code is the reference. `agent_test.go` checks every test vector below, and the Python snippet at the end checks them too.

All JSON is UTF-8. Hashes are lowercase hex SHA-256. Keys and signatures are standard base64 with padding, unless a field says otherwise. Times are Unix seconds, except `mtime_ns`.

## Transport

- The transport is HTTPS only, TLS 1.3 or later. The agent has no plain-http mode and uses no CA chain.
- The agent accepts the listener's leaf certificate only if `SHA-256(DER SubjectPublicKeyInfo)` equals the TLS pin. This is `NUMEN_AGENT_TLS_PIN`: the lowercase hex of that hash, as in `docs/implementation-contract.md`. The pin is checked on every handshake. The agent sends no client certificate.
- `enroll --url` must be `https://host[:port]`, with no user info, path, query or fragment. A path of `/` is allowed. The default port is 443.
- The host is resolved once. Every address must be loopback or private (RFC 1918, or `fc00::/7`), and a zoned address is refused.
- The agent keeps the first address in `listener_addr`, and from then on connects only to that address. It never resolves the host again and never uses a proxy.
- The `Host` header is the URL's host, and SNI is sent only when that host is a name.
- Redirects are refused.
- The listener's answer is read up to 4 MiB. A larger answer is an error.

## Routes

The routes are under `/agent/v1/` on the listener's URL:

| Method | Path | Request body | 2xx answer |
|---|---|---|---|
| POST | `/agent/v1/enroll` | enroll request | any. `202 {"status":"pending"}` is suggested, and the body is ignored |
| GET | `/agent/v1/poll?config_sequence=C&command_sequence=K&report_sequence=R` | empty | poll answer |
| POST | `/agent/v1/report` | report (File manifest) | any. `202`, and the body is ignored |
| POST | `/agent/v1/upload` | upload | any. `202`, and the body is ignored |
| POST | `/agent/v1/result` | result | any. `202`, and the body is ignored |

- The poll's query values are the highest configuration, command and report sequences the agent holds. They are informational, for the agent's row; nothing may trust them.
- Body caps (B01) are 16 MiB for a report, 16 MiB for an upload, and 64 KiB for everything else. A larger body gets `413`.
- The agent keeps every body within its cap.
- The agent polls every `poll_interval_seconds`: 30 s by default, and never under 2 s.

## Errors

Every non-2xx answer has the body `{"error": "<code>"}`. The agent logs the status and code, and tries again at its next poll. A failed report is not resent: its sequence is spent, and the next report carries a higher one.

Suggested codes:

| Status | Codes |
|---|---|
| 400 | `bad_request` |
| 401 | `bad_signature`, `clock_skew`, `nonce_reused`, `unknown_agent` |
| 403 | `revoked` |
| 404 | `not_found` |
| 413 | `request_too_large` |
| 422 | `hash_mismatch` (upload) |
| 429 | `rate_limited` |

## Request signature

Every request carries these headers, the enroll request included:

| Header | Value |
|---|---|
| `X-Agent-Id` | The agent id: `[A-Za-z0-9._:-]{1,128}`, given to `enroll --agent-id` by the dashboard |
| `X-Agent-Timestamp` | Decimal Unix seconds |
| `X-Agent-Nonce` | 32 lowercase hex characters, 16 random bytes |
| `X-Agent-Content-SHA256` | Lowercase hex SHA-256 of the exact body bytes. An empty body hashes to `e3b0c442…b855` |
| `X-Agent-Signature` | Standard base64 of the 64-byte Ed25519 signature |
| `Content-Type` | `application/json`, when the body is not empty |

The Agent key signs these bytes, which are six fields joined by a single `\n` (0x0A), with no trailing newline:

```
asset-monitor-agent-request-v1
<METHOD>
<path?query>
<X-Agent-Timestamp>
<X-Agent-Nonce>
<hex SHA-256 of the body>
```

- `<METHOD>` is the uppercase method.
- `<path?query>` is the request target exactly as it was sent: the raw path, then `?` and the raw query string if one is present. It is never decoded or re-encoded. In ASGI this is `scope["raw_path"]`, plus `b"?" + scope["query_string"]` when the query string is not empty.
- The listener checks the following, in this order:
  1. the body hash equals the header;
  2. the signature verifies with the agent's Agent key. For `enroll`, it verifies with `public_key` from the body, which proves the agent holds that key;
  3. the timestamp is within 300 s of its clock;
  4. the nonce was not seen from that agent while that timestamp is inside the window.

## Enroll

`enroll` reads the Enrollment code from standard input only: the first line, trimmed, of 8 to 256 characters from `[A-Za-z0-9._~:-]`. A suggested code is `<code id>.<32 base32 chars>`, which carries 160 bits.

The command the dashboard shows is:

```
asset-monitor-agent enroll --url https://127.0.0.1:8792 --tls-pin <NUMEN_AGENT_TLS_PIN> \
  --dashboard-key <base64 of the 32-byte Ed25519 public key> --key-id <key id> --agent-id <agent id> \
  --allow /var/www/html
```

- `--tls-pin` and `--dashboard-key` each take 64 hex digits or base64, which may be standard or URL-safe, with or without padding.
- `--key-id` and `--agent-id` take `[A-Za-z0-9._:-]{1,128}`.
- The agent stores the pin as hex and the Dashboard key as standard base64 in `/etc/asset-monitor-agent/config.json`. It stores the Agent key's seed in `agent.key`. Both files are mode 0600 and owned by root.

After **Rotate Dashboard key**, the Operator runs, as root, `asset-monitor-agent repin --key <base64 of the new 32-byte public key> --key-id <new key id>`, then `systemctl restart asset-monitor-agent`. `repin` rewrites only the Dashboard key and key id in `config.json`; the Agent key, the agent id and the sequences are kept, so the new key continues the per-agent sequence.

The request is `POST /agent/v1/enroll`, signed with the new Agent key:

```json
{"agent_id":"agent-1","enrollment_code":"<code>","public_key":"<base64 32 bytes>",
 "allowed_paths":["/var/www/html"],"version":"0.1.0","os":"linux","arch":"amd64"}
```

- `allowed_paths` are real paths, at most 32 of them, and the agent has already applied the B03 refusals to them.
- The agent writes its configuration and unit only after a 2xx answer.
- It then prints the fingerprint `sha256:<lowercase hex SHA-256 of the raw 32-byte public key>`, which the dashboard shows the same way.

## Signed messages (Dashboard key)

A configuration or a command arrives as an envelope:

```json
{"payload":"<standard base64 of the payload bytes>","signature":"<standard base64, 64 bytes>","key_id":"dk-1"}
```

- The Dashboard key signs these bytes: `asset-monitor-dashboard-message-v1` + `\n` + the payload bytes.
- The payload is any JSON serialization the dashboard chooses. The agent verifies the bytes it received and only then parses them, so no canonical JSON is needed. `json.dumps(obj, separators=(",", ":")).encode()` is fine.

The payload object:

| Field | Meaning |
|---|---|
| `v` | `1` |
| `type` | `configuration` or `command` |
| `agent_id` | Must equal the agent's id |
| `key_id` | Must equal the pinned key id, and so must the envelope's `key_id` |
| `sequence` | An integer that only increases per agent and per type. One per-agent counter shared by both types satisfies this |
| `issued_at` | Unix seconds. It is refused if more than 300 s in the future |
| `expires_at` | For a command, Unix seconds with `now < expires_at <= now + 15 min + 300 s`. For a configuration, it must be `0` |
| `body` | Depends on the type, as below |

The agent accepts a message only if its `sequence` is higher than the highest of that type it has accepted, which it keeps in `/var/lib/asset-monitor-agent/state.json`.

**Configuration body.** The configuration version is the message's `sequence`, and each report carries it as `config_sequence`.

```json
{"watched_roots":["/var/www/html"],"report_interval_seconds":3600,"poll_interval_seconds":30}
```

- `watched_roots` is not empty. Each root is an absolute real path inside an Allowed path that passes the B03 refusals. Otherwise the agent refuses the whole configuration and keeps the one it holds.
- `report_interval_seconds` is `0` when scheduled monitoring is off. Otherwise the agent reports when that many seconds have passed since its last report, checking at each poll.
- `poll_interval_seconds` is `0` for the default of 30 s, and has a floor of 2 s. The dashboard sends less than 30 only under `NUMEN_TEST_MODE`.
- The agent also reports right after it accepts a new configuration.
- The poll answer should always carry the latest configuration. The agent ignores, silently, the one whose sequence it already holds.

**Command bodies.** The set is fixed: anything else is refused with `unknown_command`. At most 100 `files` or `entries` are allowed per command.

```json
{"command_id":"cmd-1","name":"rescan"}
{"command_id":"cmd-2","name":"quarantine","files":[{"root":"/var/www/html","path":"wp-content/x.php","sha256":"<hex>"}]}
{"command_id":"cmd-3","name":"restore","entries":["<quarantine_id>"]}
```

- `command_id` is `[A-Za-z0-9._:-]{1,128}`.
- A command's sequence is spent before the command runs, so it runs at most once and is never retried.
- A command re-delivered after it ran is ignored without a result. After an agent restart, one `not_newer` refusal may still arrive for it, and the dashboard ignores a refusal for a command it already has a result for.
- The agent runs the commands of one poll answer in ascending sequence. The dashboard should keep returning every pending command until its result arrives or it expires.

## Poll answer

```json
{"configuration": <envelope or null>,
 "commands": [<envelope>, ...],
 "wanted": {"report_sequence": 12, "sha256": ["<hex>", ...]} | null}
```

- `wanted` is the one unsigned input. Its `sha256` list is in priority order: web-executable files first, then smaller files before larger ones.
- The agent acts on the list only when `report_sequence` equals the sequence of its latest report, and only once per report.
- It uploads only values from that manifest, at most 1 MiB each, never a file on the secret list, never bytes identical to a secret-list file, and only bytes it re-hashes at upload time.

## Report (File manifest)

The report is `POST /agent/v1/report`:

```json
{"sequence":12,"config_sequence":3,"reason":"scheduled","started_at":1763200000,"finished_at":1763200004,
 "file_count":2,"over_limit":false,"cut_short":false,"issues":[],
 "roots":[{"root":"/var/www/html","entries":[
   {"path":"index.php","type":"file","sha256":"<hex>","size":13,"mode":420,"uid":33,"gid":33,"mtime":1763100000},
   {"path":".env","type":"file","sha256":"<hex>","size":9,"mode":384,"uid":33,"gid":33,"mtime":1763100000,"secret":true},
   {"path":"big.iso","type":"file","size":700000000,"mode":420,"uid":0,"gid":0,"mtime":1763100000,"over_hash_limit":true},
   {"path":"shared","type":"symlink","size":11,"mode":511,"uid":0,"gid":0,"mtime":1763100000,"target":"/srv/shared"}]}]}
```

- `sequence` increases with every report and survives restarts.
- `reason` is one of `configuration`, `scheduled`, `rescan`, `quarantine` or `restore`. The last two mark the rescan after that command.
- `path` is relative to `root`, uses `/`, and is normalized. It is never `.` or `..`, and holds no NUL and at most 4,096 bytes.
- `mode` is `st_mode & 0o7777` as a decimal number, so it includes setuid, setgid and sticky.
- `uid` and `gid` are numbers, and `mtime` is in seconds.
- Each Watched root is opened from `/` one component at a time, refusing a symbolic link at any component, so a root swapped for a link after it was checked gives `root_refused`. Uploads, Quarantine and Restore open it the same way.
- Only regular files and symbolic links are listed. Directories are walked, not listed, and devices, sockets and pipes are skipped.
- A symbolic link has its `target` and is never followed: it has no `sha256`.
- `secret: true` marks a file on the secret list. Its hash is reported, and its bytes are never uploaded.
- A file over 512 MiB has `over_hash_limit: true`, with no `sha256`. So does a file that grows past 512 MiB while it is hashed: the agent never reads more than 512 MiB + 1 bytes of one file.
- An over-limit report is sent when the manifest passes 50,000 files, or when the encoded report would pass 16 MiB. It has `over_limit: true`, `roots: []`, and an issue `over_file_limit` or `report_too_large`. A manifest is never truncated.
- `cut_short` is set when the 4-minute deadline passed, or when a path was left out (`path_too_long`, `bad_name` for names that are not UTF-8). The entries walked so far are still sent.
- Each item of `issues` is `{"reason","root"?,"path"?}`. The reasons are `root_refused`, `read_error`, `deadline`, `path_too_long`, `bad_name`, `changed_during_walk`, `over_hash_limit`, `over_file_limit` and `report_too_large`.
- A report with `over_limit`, `cut_short` or any issue gives an incomplete Server change.

## Upload

The upload is `POST /agent/v1/upload`, in one or more requests per wanted list, each at most 16 MiB:

```json
{"report_sequence":12,
 "files":[{"sha256":"<hex>","content_b64":"<standard base64 of at most 1 MiB>"}],
 "skipped":[{"sha256":"<hex>","reason":"secret"}],
 "complete":true}
```

- `complete: true` is on the last request for that wanted list, even when `files` is empty. It means "the report is complete".
- The `skipped` reasons are `not_in_manifest`, `secret`, `too_large`, `gone_or_changed` and `hard_link`. `hard_link` is a file with more than one hard link, which may be another name of a file outside the Watched roots. Entries that are not 64 lowercase hex characters are dropped silently.
- The listener refuses a request whose file bytes do not hash to their `sha256`.

## Result

The result is `POST /agent/v1/result`, at most 64 KiB:

```json
{"type":"command","sequence":5,"command_id":"cmd-2","name":"quarantine","status":"done",
 "files":[{"root":"/var/www/html","path":"wp-content/x.php","sha256":"<hex>","quarantine_id":"<32 hex>","status":"quarantined"}]}
```

- `status` is `done` or `refused`, and `reason` is set when refused.
- The agent also sends `{"type":"configuration","sequence":N,"status":"done"}` when it accepts a configuration.
- It sends a refusal once for each distinct refused envelope, and at most 16 refusals per poll answer; the rest are sent at a later poll if they arrive again. The `sequence`, `command_id` and `name` of a refusal come from the payload only when its signature verified.
- The refusal reasons are `bad_payload`, `bad_signature`, `unknown_key_id`, `bad_version`, `wrong_agent`, `wrong_type`, `not_newer`, `issued_in_future`, `no_expiry`, `expired`, `expiry_too_far`, `unexpected_expiry`, `bad_body`, `too_many_files`, `unknown_command`, and `watched_root_refused: <root>: <why>`.
- `files[i]` answers the command's `files[i]` or `entries[i]`. When the result would pass 64 KiB, `root`, `path` and `detail` are dropped.
- The file statuses for a Quarantine are `quarantined`, `not_present`, `hash_mismatch`, `link_refused` and `failed`.
- The file statuses for a Restore are `restored`, `path_taken` and `failed`.
- `quarantine_id` names the entry a later Restore uses.
- A failed put-back reports `failed` with `detail` `left at .am-aside-<id>: …`.

## Quarantine and Restore on the server

These run in the state directory `/var/lib/asset-monitor-agent`, which is mode 0700:

- `quarantine/<id>.bin` holds the quarantined bytes, mode 0600.
- `quarantine/<id>.json` is the record: `{id, root, path, sha256, size, mode, uid, gid, mtime_ns, quarantined_at}`.
- `journal/<id>.json` holds an unfinished step.
- `state.json` holds the sequences and the configuration.

**Quarantine** goes through these steps:

1. It refuses a path with any symbolic link component, from `/` down to the file. It opens each directory with `os.Root` and checks that the handle is the directory `lstat` saw.
2. It checks the file's SHA-256 (a file over 512 MiB is `failed`), then renames the file within that one parent handle to `.am-aside-<id>`.
3. It opens the aside name, checks that it is the same regular file, and copies it from that descriptor into an exclusively created 0600 file.
4. It verifies the copy, writes the record, and removes the aside name.
5. On a mismatch, it puts the file back with a hard link, which never replaces a file.

**Restore** creates the file exclusively at the recorded path (`O_CREAT|O_EXCL`, which never follows a link). It copies the bytes and verifies them, then sets the owner, the mode without setuid or setgid, and the mtime on the open descriptor. Finally it removes the quarantine entry.

After a restart, the journal undoes a Quarantine that had not verified its copy, finishes one that had, and finishes or drops (only its own inode) a Restore.

## Test vectors

The Agent key seed is the bytes `00 01 02 … 1f`. The Dashboard key seed is the bytes `20 21 … 3f`.

| | Value |
|---|---|
| Agent public key | `A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=` |
| Agent fingerprint | `sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c` |
| Dashboard public key | `Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=` |

**Request 1** is a `POST` to `/agent/v1/report`, with timestamp `1763200000`, nonce `00112233445566778899aabbccddeeff` and body `{"sequence":1}`.

- Body SHA-256: `603ff4b70ceeeda2a87631465b1a7089df62b5d48e4426d1bbe9bd2c219f0bfd`
- Signed bytes: `asset-monitor-agent-request-v1\nPOST\n/agent/v1/report\n1763200000\n00112233445566778899aabbccddeeff\n603ff4b70ceeeda2a87631465b1a7089df62b5d48e4426d1bbe9bd2c219f0bfd`
- Signature: `KDJeQWvVYRHhQWv9RAPqs2gw0KOyJufUrC4zZmTmUhe24yle96ZWuN8sX6cUD+wC9UQqeMlzpfzd65s4ioc1Aw==`

**Request 2** is a `GET` to `/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0`, with the same timestamp and nonce and an empty body.

- Signature: `wZPPf2T6G3h/UKohvxV0EftI5ows1XxjkUKpGvJjcK3JZNyC2L6wNph00YwQGLSltvcSHDWIb2wdGdq1YthNBw==`

**Configuration**, with key id `dk-1` and these payload bytes:

```
{"v":1,"type":"configuration","agent_id":"agent-1","key_id":"dk-1","sequence":1,"issued_at":1763200000,"expires_at":0,"body":{"watched_roots":["/var/www/html"],"report_interval_seconds":3600,"poll_interval_seconds":30}}
```

- `payload`: `eyJ2IjoxLCJ0eXBlIjoiY29uZmlndXJhdGlvbiIsImFnZW50X2lkIjoiYWdlbnQtMSIsImtleV9pZCI6ImRrLTEiLCJzZXF1ZW5jZSI6MSwiaXNzdWVkX2F0IjoxNzYzMjAwMDAwLCJleHBpcmVzX2F0IjowLCJib2R5Ijp7IndhdGNoZWRfcm9vdHMiOlsiL3Zhci93d3cvaHRtbCJdLCJyZXBvcnRfaW50ZXJ2YWxfc2Vjb25kcyI6MzYwMCwicG9sbF9pbnRlcnZhbF9zZWNvbmRzIjozMH19`
- `signature`: `MX3Av+7cgGwi9rdyvFlxlhA0BK26jLU0GHr2Nx8unhd6Oio6ye5eUHEQzUg8qhdXHoH7Ar9hHvKa7JOhU9FmBA==`

**Command**, with these payload bytes:

```
{"v":1,"type":"command","agent_id":"agent-1","key_id":"dk-1","sequence":2,"issued_at":1763200000,"expires_at":1763200900,"body":{"command_id":"cmd-1","name":"rescan"}}
```

- `signature`: `LkOZ3EVu20RTFtqA5OqTyUV4lwnYngVuXbflAsbJFUqAFEk+Y8cnNOStls95eB7Xc+DoILRamQnUtaZt0BDdCg==`

This Python, using the backend's `cryptography`, reproduces the vectors:

```python
import base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

b64 = lambda b: base64.b64encode(b).decode()
agent = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
pub = agent.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
assert b64(pub) == "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
assert "sha256:" + hashlib.sha256(pub).hexdigest() == "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"

def signed_bytes(method, target, ts, nonce, body):
    return "\n".join(["asset-monitor-agent-request-v1", method, target, str(ts), nonce,
                      hashlib.sha256(body).hexdigest()]).encode()

nonce = "00112233445566778899aabbccddeeff"
assert b64(agent.sign(signed_bytes("POST", "/agent/v1/report", 1763200000, nonce, b'{"sequence":1}'))) == \
    "KDJeQWvVYRHhQWv9RAPqs2gw0KOyJufUrC4zZmTmUhe24yle96ZWuN8sX6cUD+wC9UQqeMlzpfzd65s4ioc1Aw=="
assert b64(agent.sign(signed_bytes("GET", "/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0",
                                   1763200000, nonce, b""))) == \
    "wZPPf2T6G3h/UKohvxV0EftI5ows1XxjkUKpGvJjcK3JZNyC2L6wNph00YwQGLSltvcSHDWIb2wdGdq1YthNBw=="

dash = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
payload = (b'{"v":1,"type":"configuration","agent_id":"agent-1","key_id":"dk-1","sequence":1,'
           b'"issued_at":1763200000,"expires_at":0,"body":{"watched_roots":["/var/www/html"],'
           b'"report_interval_seconds":3600,"poll_interval_seconds":30}}')
envelope = {"payload": b64(payload), "key_id": "dk-1",
            "signature": b64(dash.sign(b"asset-monitor-dashboard-message-v1\n" + payload))}
assert envelope["signature"] == "MX3Av+7cgGwi9rdyvFlxlhA0BK26jLU0GHr2Nx8unhd6Oio6ye5eUHEQzUg8qhdXHoH7Ar9hHvKa7JOhU9FmBA=="
```
