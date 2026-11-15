"""On-server agents, application side (B04, ADR-0007): the Dashboard key, signed configurations
and Agent commands, and verifying again every request the agent listener stored before anything
uses it. Only the app holds NUMEN_SIGNING_KEY, so only it signs; the scheduler only verifies."""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from . import agent_wire, artifacts, domain
from .models import (
    Action, Agent, AgentMessage, AgentRequest, Application, Artifact, DashboardKey, EnrollmentCode, FileManifest,
    Finding, ServerChange, now, uid, utc,
)
from .security import DomainError

CODE_LIFETIME = timedelta(hours=1)
COMMAND_LIFETIME = 900  # seconds (B04: a command expires after 15 minutes)
KEPT = timedelta(hours=1)  # processed requests are pruned after this, well past the replay window
MAX_ALLOWED_PATHS = 32
ROUTE_STATUSES = {"enroll": ("awaiting_enrollment",), "poll": ("pending", "enrolled"),
                  "report": ("enrolled",), "upload": ("enrolled",), "result": ("enrolled",)}
METHODS = {"poll": "GET"}
EXAMPLE_ALLOW = "/var/www/html"
MAX_SEQUENCE = 2**31 - 1  # the columns are Integer
# B05: the bytes a wanted list may ask for. ponytail: one 64 MiB cap per manifest, with no per-Baseline
# 128 MiB budget and no reference tracking or release of held bytes; add them when disks fill.
WANTED_FILE_LIMIT = 1024 * 1024
WANTED_TOTAL = 64 * 1024 * 1024
UPLOAD_WINDOW = timedelta(minutes=10)  # a report is complete when the agent says so, or after this
ENTRY_INTS = ("size", "mode", "uid", "gid", "mtime")
log = logging.getLogger(__name__)


def dashboard_key(db, vault):
    """The current Dashboard key, generated on first use. Its private half, the base64 seed, is
    stored encrypted under NUMEN_SIGNING_KEY. The oldest unretired key wins, so two first uses at
    once still sign with one."""
    row = db.scalar(select(DashboardKey).where(DashboardKey.retired_at.is_(None))
                    .order_by(DashboardKey.created_at, DashboardKey.id).limit(1))
    if row is None:
        seed = Ed25519PrivateKey.generate().private_bytes_raw()
        row = DashboardKey(id="dk-" + secrets.token_hex(4), public_key=agent_wire.public_key(seed),
                           private_key=vault.encrypt(base64.b64encode(seed).decode()))
        db.add(row)
        db.flush()
    return row


def sign_message(db, vault, agent, type, body, expires_in=None, idempotency_key=None, **data):
    """Signs a configuration or a command for `agent` with the Dashboard key, on the next value of
    the agent's one sequence, under its row lock. A command's id is its body's command_id."""
    key = dashboard_key(db, vault)
    if agent.key_id not in (None, key.id):
        raise DomainError("agent_pinned_to_old_key", "This agent is pinned to an older Dashboard key", 409)
    # Locked and read again here: the loaded row's sequence may be stale.
    agent.sequence = db.scalar(select(Agent.sequence).where(Agent.id == agent.id).with_for_update()) + 1
    issued = int(time.time())
    expires = issued + (expires_in or COMMAND_LIFETIME) if type == "command" else 0
    payload = json.dumps({"v": 1, "type": type, "agent_id": agent.id, "key_id": key.id, "sequence": agent.sequence,
                          "issued_at": issued, "expires_at": expires, "body": body}, separators=(",", ":"))
    seed = base64.b64decode(vault.decrypt(key.private_key))
    signed = agent_wire.envelope(seed, payload.encode(), key.id)
    message = AgentMessage(
        id=body.get("command_id") or uid(), agent_id=agent.id, type=type, sequence=agent.sequence, key_id=key.id,
        payload=signed["payload"], signature=signed["signature"], name=body.get("name") if type == "command" else None,
        expires_at=datetime.fromtimestamp(expires, timezone.utc) if expires else None, status="pending",
        idempotency_key=idempotency_key, data=data)
    db.add(message)
    db.flush()
    return message


def sign_configuration(db, vault, agent, config):
    """B04: Watched roots, the report interval (0 while scheduled monitoring is off) and the poll
    interval, which is shorter than the 30 s default only under NUMEN_TEST_MODE."""
    application = db.get(Application, agent.application_id)
    return sign_message(db, vault, agent, "configuration", {
        "watched_roots": agent.watched_roots,
        "report_interval_seconds": application.monitor_interval_seconds if application.monitor_enabled else 0,
        "poll_interval_seconds": 2 if config.test_mode else 0,
    })


def create_agent(db, vault, application, name, url, tls_pin):
    """Adds an agent awaiting Enrollment, with its one-time Enrollment code: <id>.<160 random bits
    in base32>, of which only the secret part's hash is kept. The enrollment it returns is shown
    once."""
    key = dashboard_key(db, vault)
    agent = Agent(application_id=application.id, name=name, url=url, status="awaiting_enrollment",
                  allowed_paths=[], watched_roots=[], data={})
    db.add(agent)
    db.flush()
    code_id, secret = secrets.token_hex(8), base64.b32encode(secrets.token_bytes(20)).decode()
    code = EnrollmentCode(id=code_id, agent_id=agent.id, secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
                          expires_at=now() + CODE_LIFETIME)
    db.add(code)
    db.flush()
    command = (f"asset-monitor-agent enroll --url {url} --tls-pin {tls_pin} --dashboard-key {key.public_key}"
               f" --key-id {key.id} --agent-id {agent.id} --allow {EXAMPLE_ALLOW}")
    return agent, {"code": f"{code_id}.{secret}", "command": command, "url": url, "tls_pin": tls_pin,
                   "dashboard_key": key.public_key, "key_id": key.id, "agent_id": agent.id,
                   "expires_at": code.expires_at.isoformat()}


def stamp(value):
    return utc(value).isoformat() if value else None


def message_json(message):
    result = (message.data or {}).get("result") or {}
    return {"id": message.id, "type": message.type, "name": message.name, "sequence": message.sequence,
            "status": message.status, "reason": result.get("reason"), "result": result or None,
            "expires_at": stamp(message.expires_at), "created_at": stamp(message.created_at)}


def agent_json(db, agent):
    """An agent as the Server files tab shows it. Everything it reports is shown as text."""
    configuration = db.scalar(select(AgentMessage).where(
        AgentMessage.agent_id == agent.id, AgentMessage.type == "configuration")
        .order_by(AgentMessage.sequence.desc()).limit(1))
    commands = db.scalars(select(AgentMessage).where(
        AgentMessage.agent_id == agent.id, AgentMessage.type == "command")
        .order_by(AgentMessage.sequence.desc()).limit(10))
    data = agent.data or {}
    baseline = agent.baseline_manifest_id and db.get(FileManifest, agent.baseline_manifest_id)
    latest = db.scalar(select(FileManifest).where(FileManifest.agent_id == agent.id)
                       .order_by(FileManifest.sequence.desc()).limit(1))
    changes = db.scalars(select(ServerChange).where(ServerChange.agent_id == agent.id)
                         .order_by(ServerChange.created_at.desc()).limit(20))
    return {
        "id": agent.id, "application_id": agent.application_id, "name": agent.name, "url": agent.url,
        "status": agent.status, "fingerprint": agent.fingerprint, "key_id": agent.key_id,
        "allowed_paths": agent.allowed_paths or [], "watched_roots": agent.watched_roots or [],
        "version": data.get("version"), "os": data.get("os"), "arch": data.get("arch"), "poll": data.get("poll"),
        "config_sequence": agent.config_sequence, "report_sequence": agent.report_sequence,
        "last_seen_at": stamp(agent.last_seen_at), "last_refusal": agent.last_refusal,
        "created_at": stamp(agent.created_at), "revoked_at": stamp(agent.revoked_at),
        "configuration": message_json(configuration) if configuration else None,
        "commands": [message_json(message) for message in commands],
        "baseline": {"manifest_id": baseline.id, "sha256": baseline.sha256,
                     "accepted_at": data.get("baseline_accepted_at")} if baseline else None,
        "latest_manifest": latest and {
            "id": latest.id, "sequence": latest.sequence, "sha256": latest.sha256, "status": latest.status,
            "file_count": len(latest.entries), "incomplete": latest.incomplete, "created_at": stamp(latest.created_at)},
        "accept_allowed": bool(latest and baseline_refusal(db, agent, latest) is None),
        # The server_files Finding a Malicious change Verdict opened for each change, if any.
        "changes": [{**domain.server_change_json(db, change), "finding_id": db.scalar(select(Finding.id).where(
            Finding.source == "server_files", Finding.data["subject_id"].as_string() == change.id))}
            for change in changes],
    }


def refusal(request, agent, body):
    """Why a stored request must not be used, or None: its body hash, its target, its signature
    (with the bound Agent key, or for an Enrollment the key it presents), its timestamp against
    the time Postgres received it, and the agent's status. Its nonce is unique per agent by the
    table's key."""
    if hashlib.sha256(request.body).hexdigest() != request.content_sha256:
        return "body_hash_mismatch"
    if (request.method != METHODS.get(request.route, "POST")
            or request.target.partition("?")[0] != f"/agent/v1/{request.route}"):
        return "bad_request"
    key = body.get("public_key") if request.route == "enroll" and isinstance(body, dict) else agent.public_key
    signed = agent_wire.signed_bytes(request.method, request.target, request.timestamp, request.nonce,
                                     request.content_sha256)
    if not agent_wire.verify(key, request.signature, signed):
        return "bad_signature"
    if abs(request.timestamp - utc(request.received_at).timestamp()) > agent_wire.WINDOW:
        return "clock_skew"
    if agent.status not in ROUTE_STATUSES[request.route]:
        return {"pending": "agent_pending", "revoked": "revoked"}.get(agent.status, "agent_status")
    if request.route != "poll" and not isinstance(body, dict):
        return "bad_request"
    return None


def enroll(db, agent, request, body, root):
    """Checks and spends the Enrollment code, then binds the Agent key; the agent is pending until
    the Operator confirms its fingerprint."""
    code_id, _, secret = str(body.get("enrollment_code") or "").partition(".")
    code = db.get(EnrollmentCode, code_id, with_for_update=True) if code_id else None
    if (code is None or code.agent_id != agent.id or code.used_at is not None
            or utc(code.expires_at) <= utc(request.received_at)
            or not hmac.compare_digest(code.secret_hash, hashlib.sha256(secret.encode()).hexdigest())):
        return "enrollment_refused"
    paths, info = body.get("allowed_paths"), [body.get(name) for name in ("version", "os", "arch")]
    if (body.get("agent_id") != agent.id or not isinstance(paths, list) or not 0 < len(paths) <= MAX_ALLOWED_PATHS
            or not all(isinstance(path, str) and path.startswith("/") and len(path) <= agent_wire.MAX_PATH
                       for path in paths)
            or not all(isinstance(value, str) and len(value) <= 64 for value in info)):
        return "bad_request"
    code.used_at = now()
    agent.public_key, agent.fingerprint = body["public_key"], agent_wire.fingerprint(body["public_key"])
    agent.allowed_paths, agent.status = paths, "pending"
    agent.data = {**(agent.data or {}), **dict(zip(("version", "os", "arch"), info))}
    return None


def poll(db, agent, request, body, root):
    """Last seen comes from verified polls only. The query is informational."""
    query = dict(parse_qsl(request.target.partition("?")[2]))
    agent.last_seen_at = utc(request.received_at)
    agent.data = {**(agent.data or {}), "poll": {
        name: int(query[name]) for name in ("config_sequence", "command_sequence", "report_sequence")
        if query.get(name, "").isdigit() and len(query[name]) <= 18}}
    return None


def manifest_entries(agent, body):
    """A report's entries flattened, each with its root, sorted by (root, path), or a refusal: every
    root must be a Watched root and every path pass valid_path, as at the listener."""
    entries = {}
    roots = body.get("roots")
    if not isinstance(roots, list):
        return None, "bad_request"
    for item in roots:
        root = item.get("root") if isinstance(item, dict) else None
        if root not in agent.watched_roots or not isinstance(item.get("entries"), list):
            return None, "root_not_watched"
        for raw in item["entries"]:
            if not isinstance(raw, dict) or not agent_wire.valid_path(raw.get("path")):
                return None, "bad_path"
            sha, target = raw.get("sha256"), raw.get("target")
            if (raw.get("type") not in ("file", "symlink") or not all(type(raw.get(k)) is int for k in ENTRY_INTS)
                    or not (sha is None or (isinstance(sha, str) and agent_wire.SHA256.fullmatch(sha)))
                    or not (target is None or isinstance(target, str) and len(target) <= agent_wire.MAX_PATH)):
                return None, "bad_request"
            entry = {"root": root, "path": raw["path"], "type": raw["type"], "sha256": sha,
                     **{k: raw[k] for k in ENTRY_INTS}}
            if target is not None:
                entry["target"] = target
            for flag in ("secret", "over_hash_limit"):
                if raw.get(flag) is True:
                    entry[flag] = True
            entries[(root, raw["path"])] = entry
    return [entries[key] for key in sorted(entries)], None


def secret(entry):
    """On the secret list, by the agent's flag or by the dashboard's own copy of the list."""
    return entry.get("secret") is True or agent_wire.is_secret(entry["root"] + "/" + entry["path"])


def web_executable(entry):
    return entry["path"].lower().endswith(agent_wire.WEB_EXECUTABLE)


def held(db, digests):
    """The SHA-256 values among `digests` whose bytes are held as server_files artifacts."""
    digests = sorted(set(digests))
    return set(db.scalars(select(Artifact.resource_id).where(
        Artifact.resource_type == "server_files", Artifact.resource_id.in_(digests)))) if digests else set()


def wanted_list(db, entries):
    """B05: the hashed, not secret files of at most 1 MiB whose bytes are not held, web-executable
    files first and then smaller before larger, within WANTED_TOTAL."""
    files = sorted((entry for entry in entries if entry["type"] == "file" and entry["sha256"]
                    and not secret(entry) and not entry.get("over_hash_limit") and entry["size"] <= WANTED_FILE_LIMIT),
                   key=lambda entry: (not web_executable(entry), entry["size"], entry["sha256"]))
    # The bytes of a secret file are never asked for, even when another path holds the same bytes.
    skip = held(db, (entry["sha256"] for entry in files)) | {entry["sha256"] for entry in entries if secret(entry)}
    wanted, total = {}, 0
    for entry in files:
        sha = entry["sha256"]
        if sha in skip or sha in wanted or total + entry["size"] > WANTED_TOTAL:
            continue
        wanted[sha] = None
        total += entry["size"]
    return list(wanted)


def report(db, agent, request, body, root):
    """B05: a verified report becomes a File manifest, answered with a wanted list. A report whose
    sequence does not increase, a root that is not Watched or a bad path refuses it; one run under
    an older configuration is stored, and noted as the agent's last refusal. An older manifest
    still awaiting uploads is completed first: the agent uploads only for its latest report."""
    sequence, config_sequence = body.get("sequence"), body.get("config_sequence")
    if type(sequence) is not int or not agent.report_sequence < sequence <= MAX_SEQUENCE:
        return "report_sequence_not_increasing"
    if type(config_sequence) is not int or not 0 <= config_sequence <= MAX_SEQUENCE:
        return "bad_request"
    entries, refused = manifest_entries(agent, body)
    if refused:
        return refused
    agent.report_sequence = sequence
    for older in list(db.scalars(select(FileManifest).where(
            FileManifest.agent_id == agent.id, FileManifest.status == "awaiting_uploads"))):
        complete_manifest(db, root, older)
    issues = body.get("issues") if isinstance(body.get("issues"), list) else []
    incomplete = [{key: str(issue[key])[:agent_wire.MAX_PATH] for key in ("reason", "root", "path") if key in issue}
                  for issue in issues if isinstance(issue, dict) and "reason" in issue][:100]
    incomplete += [{"reason": flag} for flag in ("over_limit", "cut_short") if body.get(flag) is True]
    reason = body.get("reason")
    manifest = FileManifest(
        agent_id=agent.id, request_id=request.id, sequence=sequence, config_sequence=config_sequence,
        reason=reason if isinstance(reason, str) and len(reason) <= 32 else None, entries=entries, incomplete=incomplete,
        sha256=hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        status="awaiting_uploads")
    db.add(manifest)
    db.flush()
    wanted = wanted_list(db, entries)
    agent.wanted = {"report_sequence": sequence, "sha256": wanted} if wanted else None
    if not wanted:
        complete_manifest(db, root, manifest)
    if config_sequence != agent.config_sequence:
        agent.last_refusal = {"at": now().isoformat(), "route": "report", "reason": "old_configuration"}
    return None


def upload(db, agent, request, body, root):
    """B05: the bytes of the latest manifest's wanted list. Application code hashes each file again
    and holds only bytes the list asked for, as a server_files artifact keyed by SHA-256; they are
    never executed or rendered. complete: true completes the manifest. An upload for a manifest
    that is already complete is ignored."""
    sequence, files = body.get("report_sequence"), body.get("files") or []
    manifest = type(sequence) is int and db.scalar(select(FileManifest).where(
        FileManifest.agent_id == agent.id, FileManifest.sequence == sequence).with_for_update())
    if not manifest or manifest.status != "awaiting_uploads":
        return None
    if not isinstance(files, list) or not all(isinstance(item, dict) for item in files):
        return "bad_request"
    wanted = set((agent.wanted or {}).get("sha256") or ()) if (agent.wanted or {}).get("report_sequence") == sequence else set()
    contents = {}
    for item in files:
        try:
            data = base64.b64decode(item.get("content_b64") or "", validate=True)
        except (TypeError, ValueError):
            return "bad_request"
        if hashlib.sha256(data).hexdigest() != item.get("sha256"):
            return "hash_mismatch"  # every file is checked before any is held
        contents[item["sha256"]] = data
    have = held(db, contents)
    for sha, data in contents.items():
        if sha in wanted and sha not in have and len(data) <= WANTED_FILE_LIMIT:
            artifacts.publish(db, root, "server_files", sha, {"content": data})
    if body.get("complete") is True:
        complete_manifest(db, root, manifest)
        agent.wanted = None
    return None


def identity(entry):
    """What a Server change compares (B05): type, SHA-256 (size and mtime for a file over the hash
    limit), mode, owner and link target. mtime alone is never a change."""
    content = [entry.get("size"), entry.get("mtime")] if entry.get("over_hash_limit") else entry.get("sha256")
    return [entry["type"], content, entry.get("mode"), entry.get("uid"), entry.get("gid"), entry.get("target")]


def manifest_diff(before, after):
    """{added, modified: [{before, after}], removed} from one manifest's entries to another's, by (root, path)."""
    old = {(entry["root"], entry["path"]): entry for entry in before}
    new = {(entry["root"], entry["path"]): entry for entry in after}
    return {"added": [new[key] for key in sorted(new.keys() - old.keys())],
            "modified": [{"before": old[key], "after": new[key]} for key in sorted(old.keys() & new.keys())
                         if identity(old[key]) != identity(new[key])],
            "removed": [old[key] for key in sorted(old.keys() - new.keys())]}


def change_fingerprint(diff):
    """The Server change's identity: the SHA-256 of its diff's identities, so mtime never counts."""
    key = {"added": [[e["root"], e["path"], identity(e)] for e in diff["added"]],
           "modified": [[m["after"]["root"], m["after"]["path"], identity(m["before"]), identity(m["after"])]
                        for m in diff["modified"]],
           "removed": [[e["root"], e["path"], identity(e)] for e in diff["removed"]]}
    return hashlib.sha256(json.dumps(key, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def missing(entry, have):
    """Why an added or changed file's bytes are not held, or None."""
    return ("secret" if secret(entry) else "over_hash_limit" if entry.get("over_hash_limit")
            else "not_hashed" if not entry["sha256"] else "too_large" if entry["size"] > WANTED_FILE_LIMIT
            else None if entry["sha256"] in have else "not_uploaded")


def record_server_change(db, agent, manifest, baseline, diff):
    """The Server change of `manifest` against the Baseline (B05): one per (agent, fingerprint), as
    record_served_change keeps one per served fingerprint, kept with the first manifest that showed
    it. It is incomplete with its report's reasons and each added or changed file whose bytes are
    not held. A new one queues its one Triage."""
    fingerprint = change_fingerprint(diff)
    query = select(ServerChange).where(ServerChange.agent_id == agent.id, ServerChange.fingerprint == fingerprint)
    row = db.scalar(query)
    if row is None:
        files = [e for e in [*diff["added"], *(m["after"] for m in diff["modified"])] if e["type"] == "file"]
        have = held(db, (e["sha256"] for e in files if e["sha256"]))
        incomplete = [*manifest.incomplete, *({"reason": why, "root": e["root"], "path": e["path"]}
                                              for e in files if (why := missing(e, have)))]
        try:
            with db.begin_nested():
                row = ServerChange(application_id=agent.application_id, agent_id=agent.id, fingerprint=fingerprint,
                                   manifest_id=manifest.id, baseline_manifest_id=baseline.id, diff=diff,
                                   incomplete=incomplete)
                db.add(row)
                db.flush()
                domain.queue_server_triage(db, db.get(Application, agent.application_id), row)
        except IntegrityError:
            row = db.scalar(query)
    return row


def complete_manifest(db, root, manifest):
    """Completes a File manifest and compares it with the agent's Baseline. Before a Baseline is
    accepted nothing is compared, so a first report starts no Triage. Returns the Server change it
    shows, or None when it matches the Baseline."""
    manifest.status, manifest.completed_at = "complete", now()
    agent = db.get(Agent, manifest.agent_id)
    finding_lifecycle(db, agent, manifest)
    if agent.baseline_manifest_id is None:
        return None
    baseline = db.get(FileManifest, agent.baseline_manifest_id)
    diff = manifest_diff(baseline.entries, manifest.entries)
    if not any(diff.values()):
        return None
    return record_server_change(db, agent, manifest, baseline, diff)


def finding_lifecycle(db, agent, manifest):
    """B07: a verified manifest with none of a server_files Finding's named SHA-256 values moves it
    to Remediated; one that shows a named value again moves a Remediated one back to Confirmed,
    with an Alert whose source is the agent's name and which carries no path. ponytail: by named
    SHA-256 only, with no check against the Baseline; only a manifest with no incomplete reason
    remediates, while any manifest may regress."""
    seen = {entry["sha256"] for entry in manifest.entries if entry.get("sha256")}
    findings = db.scalars(select(Finding).where(
        Finding.source == "server_files", Finding.data["agent_id"].as_string() == agent.id,
        Finding.status.in_(("open", "confirmed", "remediated"))).order_by(Finding.created_at))
    for finding in list(findings):
        named = domain.named_sha256(finding)
        if not named:
            continue
        if finding.status in ("open", "confirmed") and not manifest.incomplete and not named & seen:
            domain.transition_finding(db, finding, "remediated", {"by": "manifest", "manifest_id": manifest.id})
        elif finding.status == "remediated" and named & seen and domain.transition_finding(
                db, finding, "confirmed", {"by": "regression", "manifest_id": manifest.id}):
            finding.data = {**finding.data, "regressed_at": now().isoformat()}
            domain.notify(db, f"finding:{finding.id}:regressed:{manifest.id}", verdict="Malicious change · regressed",
                          application=db.get(Application, finding.application_id).asset_name, source=agent.name,
                          link=f"/findings/{finding.id}")


def approved_command(db, vault, agent, finding, name, scope, body, **data):
    """B07: the Quarantine or Restore command of an Approval, signed under the agent's row lock,
    which the caller holds. A pending, unexpired command for the same scope is returned as is, so a
    double submit signs one command; otherwise attempt n, the count of earlier ones, is in its
    idempotency key. The Approval is recorded as an Action on the Finding."""
    prefix = f"{name}:{scope}:"
    earlier = list(db.scalars(select(AgentMessage).where(
        AgentMessage.agent_id == agent.id, AgentMessage.idempotency_key.startswith(prefix, autoescape=True))))
    pending = next((m for m in earlier if domain.command_state(m) == "pending"), None)
    if pending is not None:
        return pending
    message = sign_message(db, vault, agent, "command", {"command_id": uid(), "name": name, **body},
                           idempotency_key=prefix + str(len(earlier)), finding_id=finding.id, **data)
    db.add(Action(resource_type="finding", resource_id=finding.id, data={
        "action": "approved", "approved": name, "command_id": message.id, **data}))
    return message


def baseline_refusal(db, agent, manifest):
    """Why `manifest` cannot become the agent's Baseline now, or None (B05): a first Baseline is
    always allowed; a later one only when the Server change it shows is baseline_allowed and no
    Malicious change. Its own Baseline, or a manifest that matches it, is "unchanged"."""
    if manifest.agent_id != agent.id or manifest.status != "complete" or agent.status != "enrolled":
        return "invalid_baseline"
    if agent.baseline_manifest_id is None:
        return None
    if agent.baseline_manifest_id == manifest.id:
        return "unchanged"
    diff = manifest_diff(db.get(FileManifest, agent.baseline_manifest_id).entries, manifest.entries)
    if not any(diff.values()):
        return "unchanged"
    change = db.scalar(select(ServerChange).where(
        ServerChange.agent_id == agent.id, ServerChange.fingerprint == change_fingerprint(diff)))
    if change is None or change.verdict == "Malicious change" or not domain.baseline_allowed(change):
        return "baseline_not_allowed"
    return None


def accept_baseline(db, agent, manifest_id, manifest_sha256):
    """The Operator accepts a complete File manifest as the agent's Baseline (B05), naming its
    SHA-256 so a stale one is refused. It is not an Approval and needs no password, and records an
    Action. Accepting the current Baseline again changes nothing."""
    db.refresh(agent, with_for_update=True)
    manifest = db.get(FileManifest, manifest_id)
    reason = "invalid_baseline" if manifest is None else baseline_refusal(db, agent, manifest)
    if reason == "invalid_baseline":
        raise DomainError("invalid_baseline", "Only a complete File manifest of this enrolled agent can become its"
                          " Baseline", 422)
    if not hmac.compare_digest(manifest.sha256, manifest_sha256):
        raise DomainError("manifest_changed", "That File manifest is not the one shown; reload the Server files tab", 409)
    if reason == "baseline_not_allowed":
        raise DomainError("baseline_not_allowed", "A new Baseline needs a Security hardening or Unrelated Verdict on its"
                          " Server change, a Triage that declined it, or its dismissal from the Review queue", 409)
    if reason == "unchanged":
        return
    previous = agent.baseline_manifest_id
    agent.baseline_manifest_id = manifest.id
    agent.data = {**(agent.data or {}), "baseline_accepted_at": now().isoformat()}
    db.add(Action(resource_type="agent", resource_id=agent.id, data={
        "action": "baseline_accepted", "manifest_id": manifest.id, "sha256": manifest.sha256, "previous": previous}))


def result(db, agent, request, body, root):
    """The agent's answer to a configuration or command it received: matched by type, sequence and,
    for a command, command_id. A refusal for a message that already has a done result is the
    after-restart not_newer one, and is ignored."""
    kind, sequence, status = body.get("type"), body.get("sequence"), body.get("status")
    if (kind not in ("configuration", "command") or status not in ("done", "refused")
            or type(sequence) is not int or not 0 <= sequence <= MAX_SEQUENCE):
        return "bad_request"
    message = db.scalar(select(AgentMessage).where(
        AgentMessage.agent_id == agent.id, AgentMessage.type == kind, AgentMessage.sequence == sequence))
    if message is None or (kind == "command" and body.get("command_id") != message.id):
        return f"agent_refused: {str(body.get('reason'))[:200]}" if status == "refused" else "unknown_message"
    if status == "refused" and message.status == "done":
        return None
    message.status, message.updated_at = status, now()
    message.data = {**(message.data or {}), "result": body}
    if kind == "configuration" and status == "done":
        agent.config_sequence = max(agent.config_sequence, message.sequence)
    return None


HANDLERS = {"enroll": enroll, "poll": poll, "report": report, "upload": upload, "result": result}


def process_request(db, request, artifact_root):
    agent = db.get(Agent, request.agent_id, with_for_update=True)
    try:
        body = json.loads(request.body) if request.body else None
    except ValueError:
        body = None
    reason = refusal(request, agent, body)
    if reason is None:
        reason = HANDLERS[request.route](db, agent, request, body, artifact_root)
    request.processed_at = now()
    request.outcome = {"status": "refused" if reason else "accepted", "reason": reason}
    if reason:
        agent.last_refusal = {"at": now().isoformat(), "route": request.route, "reason": reason}


def process_agent_requests(factory, artifact_root):
    """The scheduler's pass over the agent listener's stored requests, one transaction each, under
    SKIP LOCKED so two schedulers never take one. It also expires pending commands past their
    expiry, prunes processed requests older than an hour and completes File manifests whose
    uploads did not arrive within 10 minutes (their missing bytes make the change incomplete)."""
    with factory() as db:
        late = list(db.execute(select(FileManifest.id, FileManifest.agent_id).where(
            FileManifest.status == "awaiting_uploads", FileManifest.created_at < now() - UPLOAD_WINDOW)))
    for manifest_id, agent_id in late:
        with factory.begin() as db:
            agent = db.get(Agent, agent_id, with_for_update=True)  # the agent first, as process_request locks
            manifest = db.get(FileManifest, manifest_id, populate_existing=True)
            if manifest.status != "awaiting_uploads":
                continue
            try:
                with db.begin_nested():
                    complete_manifest(db, artifact_root, manifest)
            except Exception as exc:
                log.warning("Completing File manifest %s failed: %s", manifest.id, type(exc).__name__)
                manifest.status, manifest.completed_at = "complete", now()
            if (agent.wanted or {}).get("report_sequence") == manifest.sequence:
                agent.wanted = None
    with factory.begin() as db:
        db.execute(update(AgentMessage).where(
            AgentMessage.status == "pending", AgentMessage.expires_at.is_not(None), AgentMessage.expires_at <= now(),
        ).values(status="expired", updated_at=now()))
        db.execute(delete(AgentRequest).where(
            AgentRequest.processed_at.is_not(None), AgentRequest.received_at < now() - KEPT))
    while True:
        with factory.begin() as db:
            request = db.scalar(select(AgentRequest).where(AgentRequest.processed_at.is_(None))
                                .order_by(AgentRequest.received_at, AgentRequest.timestamp, AgentRequest.id)
                                .limit(1).with_for_update(skip_locked=True))
            if request is None:
                return
            try:
                with db.begin_nested():
                    process_request(db, request, artifact_root)
            except Exception as exc:
                # A request that breaks its handler is refused, so it cannot stop the scheduler. Only
                # the class is logged: the error text could hold what the agent sent.
                log.warning("Processing agent request %s failed: %s", request.id, type(exc).__name__)
                request.processed_at = now()
                request.outcome = {"status": "refused", "reason": "processing_error"}
