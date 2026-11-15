"""File manifests, Server changes and their Triage and Analysis (B05, B06, B07), end to end through
the agent listener, application code as the scheduler runs it, the worker and the API: a verified
report becomes a File manifest answered with a wanted list, uploads are hashed again before they are
held, the Operator accepts the first manifest as the Baseline, and each distinct Server change is
triaged once and analysed from its stored bytes only. A Malicious change opens a server_files
Finding whose Alert names the agent. Every agent reply comes from FixtureBroker; nothing runs the
uploaded bytes."""
import base64
import hashlib
import json

import pytest
from sqlalchemy import func, select

from conftest import FixtureBroker, connection
from numen import ingress
from numen.models import Action, Analysis, Artifact, FileManifest, Finding, Job, Notification, ServerChange
from numen.worker import run_once
from test_artifacts import APPROVAL
from test_server_agents import enrolled, outcomes, process, shown, stand  # noqa: F401
from test_triage import reply

ROOT = "/var/www/html"
SHELL = (b"<?php /* stand-in dropped shell: if run it would only print a marker */ "
         b"if (isset($_GET['c'])) { echo 'asset-monitor-fixture'; } ?>")
SHELL_PATH = "wp-content/uploads/cache.php"
FLAGGED = {"decision": "security_candidate", "title": "A PHP file was dropped in an uploads folder",
           "reason": "A new web-executable file appeared where only media belongs"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Server:
    """The stand-in server's files and its agent's reports, with the bytes to upload when asked."""

    def __init__(self, standing):
        self.stand, self.sequence, self.bytes = standing, 0, {}
        self.files = {"index.php": self.file("index.php", b"<?php echo 'Toko Batik Sari';\n"),
                      "style.css": self.file("style.css", b"body { font-family: serif; }\n"),
                      "wp-config.php": self.file("wp-config.php", b"<?php define('DB_PASSWORD', 'x');\n", secret=True)}

    def file(self, path, data, **values):
        self.bytes[sha(data)] = data
        return {"path": path, "type": "file", "sha256": sha(data), "size": len(data), "mode": 0o644, "uid": 33,
                "gid": 33, "mtime": 1763100000, **values}

    def report(self, upload=True, **extra):
        """One report of the current files, then the upload the poll's wanted list asks for. Returns the wanted list."""
        self.sequence += 1
        body = {"sequence": self.sequence, "config_sequence": 1, "reason": "rescan", "started_at": 1763200000,
                "finished_at": 1763200001, "file_count": len(self.files), "over_limit": False, "cut_short": False,
                "issues": [], "roots": [{"root": ROOT, "entries": list(self.files.values())}], **extra}
        assert self.stand.agent.send("POST", "/agent/v1/report", body) == (202, {"status": "accepted"})
        process(self.stand)
        wanted = self.stand.agent.poll()[1]["wanted"]
        if upload and wanted:
            assert wanted["report_sequence"] == self.sequence
            files = [{"sha256": digest, "content_b64": base64.b64encode(self.bytes[digest]).decode()}
                     for digest in wanted["sha256"]]
            sent = self.stand.agent.send("POST", "/agent/v1/upload", {
                "report_sequence": self.sequence, "files": files, "skipped": [], "complete": True})
            assert sent[0] == 202, sent
            process(self.stand)
        return wanted


@pytest.fixture
def server(system, stand):  # noqa: F811
    """An enrolled agent that accepted its first configuration, on an Application with Pi Triage."""
    app, client, _ = system
    connection(app)
    enrolled(stand)
    assert stand.agent.send("POST", "/agent/v1/result", {"type": "configuration", "sequence": 1, "status": "done"})[0] == 202
    process(stand)
    stand.app = app
    return Server(stand)


def triage(server, mode):
    response = server.stand.client.patch(f"/api/applications/{server.stand.application_id}",
                                         json={"config": {"triage_mode": mode}})
    assert response.status_code == 200, response.text


def latest(server):
    return shown(server.stand)["latest_manifest"]


def accept(server, manifest=None):
    manifest = manifest or latest(server)
    return server.stand.client.post(f"/api/agents/{server.stand.agent.agent_id}/baselines",
                                    json={"manifest_id": manifest["id"], "manifest_sha256": manifest["sha256"]})


def baselined(server):
    server.report()
    accepted = accept(server)
    assert accepted.status_code == 200, accepted.text


def changes(server):
    with server.stand.factory() as db:
        return list(db.scalars(select(ServerChange).order_by(ServerChange.created_at)))


def jobs(server, kind=None):
    with server.stand.factory() as db:
        query = select(Job).order_by(Job.created_at)
        return list(db.scalars(query.where(Job.kind == kind) if kind else query))


def assessment(verdict, files=()):
    malicious = {"indicators": {"files": list(files), "hosts": [], "urls": [], "commands": []},
                 "reachable_secrets": ["The database password in wp-config.php"]} if verdict == "Malicious change" else {}
    return {**malicious, "verdict": verdict, "confidence": "high", "title": "A dropped PHP shell",
            "summary": "A PHP file that runs a request parameter", "evidence": [{"path": "source/changed/x"}],
            "open_questions": []}


def broker(analysis=None, triage=FLAGGED):
    def answer(call):
        if call["profile"]["operation"] == "commit_triage":
            return reply(triage), {}
        return analysis, {"report.md": b"# A dropped PHP shell"}
    return FixtureBroker(handler=answer)


def work(server, fixture):
    while run_once(server.stand.config, server.stand.factory, fixture):
        pass


def drop_shell(server):
    server.files[SHELL_PATH] = server.file(SHELL_PATH, SHELL)
    return server.report()


def test_a_first_report_is_a_manifest_whose_wanted_list_skips_secrets_and_large_files(server):
    """B05: the wanted list asks only for hashed, not secret files of at most 1 MiB that are not held,
    web-executable first, then smaller first; the first report starts no Triage until it is accepted."""
    triage(server, "pi")
    big = server.file("backup.tar", b"x")
    server.files.update({
        "a.js": server.file("a.js", b"var a = 1;"),
        ".git/config": server.file(".git/config", b"[core]\n"),
        "id_rsa": server.file("id_rsa", b"key"),
        "id_rsa.pub": server.file("id_rsa.pub", b"ssh-ed25519 AAAA"),
        "backup.tar": {**big, "size": 2 * 1024 * 1024},
        "huge.iso": {"path": "huge.iso", "type": "file", "sha256": None, "size": 700_000_000, "mode": 0o644,
                     "uid": 0, "gid": 0, "mtime": 1, "over_hash_limit": True},
        "shared": {"path": "shared", "type": "symlink", "sha256": None, "size": 11, "mode": 0o777, "uid": 0,
                   "gid": 0, "mtime": 1, "target": "/srv/shared"},
    })
    files = server.files
    wanted = server.report()
    assert wanted["sha256"] == [files[p]["sha256"] for p in ("a.js", "index.php", "id_rsa.pub", "style.css")]
    manifest = latest(server)
    assert (manifest["status"], manifest["file_count"], manifest["incomplete"]) == ("complete", 10, [])
    with server.stand.factory() as db:
        held = set(db.scalars(select(Artifact.resource_id).where(Artifact.resource_type == "server_files",
                                                                 Artifact.path == "content")))
        row = db.get(FileManifest, manifest["id"])
        assert row.sha256 == sha(json.dumps(row.entries, sort_keys=True, separators=(",", ":")).encode())
        assert {entry["path"]: entry.get("target") for entry in row.entries}["shared"] == "/srv/shared"
    assert held == set(wanted["sha256"])
    assert (changes(server), jobs(server, "server_triage")) == ([], [])
    row = shown(server.stand)
    assert (row["baseline"], row["accept_allowed"]) == (None, True)
    # A stale manifest SHA-256 is refused; the right one is accepted, with an Action and no password.
    stale = server.stand.client.post(f"/api/agents/{server.stand.agent.agent_id}/baselines",
                                     json={"manifest_id": manifest["id"], "manifest_sha256": "0" * 64})
    assert (stale.status_code, stale.json()["code"]) == (409, "manifest_changed")
    accepted = accept(server)
    assert accepted.status_code == 200, accepted.text
    assert (accepted.json()["baseline"]["manifest_id"], accepted.json()["accept_allowed"]) == (manifest["id"], False)
    assert accept(server).status_code == 200  # the same Baseline again changes nothing
    with server.stand.factory() as db:
        (action,) = db.scalars(select(Action).where(Action.data["action"].as_string() == "baseline_accepted"))
        assert (action.resource_id, action.data["manifest_id"], action.data["previous"]) == (
            server.stand.agent.agent_id, manifest["id"], None)
    # The same files again: no Server change, and nothing new is wanted.
    assert server.report() is None
    assert changes(server) == []


def test_added_modified_and_removed_files_give_changes_and_an_mtime_only_change_does_not(server):
    """AC-B05: adding a file, changing its bytes, mode or owner, or removing it gives a Server change;
    changing only its modification time does not."""
    baselined(server)
    server.files["index.php"] = {**server.files["index.php"], "mtime": 1763999999}
    server.report()
    assert changes(server) == []
    for change in (
        {"mode": 0o755},
        {"uid": 0},
        {**server.file("index.php", b"<?php echo 'Toko Batik Sari v2';\n"), "mtime": 5},
    ):
        server.files["index.php"] = {**server.files["index.php"], **change}
        server.report()
        server.files["index.php"] = server.file("index.php", b"<?php echo 'Toko Batik Sari';\n")
    del server.files["style.css"]
    server.report()
    server.files["style.css"] = server.file("style.css", b"body { font-family: serif; }\n")
    drop_shell(server)
    found = changes(server)
    assert [(len(c.diff["added"]), len(c.diff["modified"]), len(c.diff["removed"])) for c in found] == [
        (0, 1, 0), (0, 1, 0), (0, 1, 0), (0, 0, 1), (1, 0, 0)]
    mode, owner, content, removed, added = found
    assert (mode.diff["modified"][0]["before"]["mode"], mode.diff["modified"][0]["after"]["mode"]) == (0o644, 0o755)
    assert owner.diff["modified"][0]["after"]["uid"] == 0
    assert removed.diff["removed"][0]["path"] == "style.css"
    assert (added.diff["added"][0]["path"], added.diff["added"][0]["sha256"], added.incomplete) == (
        SHELL_PATH, sha(SHELL), [])
    assert all(c.triage_status == "disabled" for c in found)  # Triage off: recorded, untriaged
    listed = shown(server.stand)["changes"][0]
    assert (listed["id"], listed["held"], listed["finding_id"]) == (added.id, [sha(SHELL)], None)


def test_ten_reports_of_one_change_give_one_change_and_one_triage_run(server):
    """AC-B05: ten reports of the same Server change start one Triage run; after its Unrelated
    Verdict the Operator may accept the later manifest as the Baseline."""
    baselined(server)
    triage(server, "pi")
    fixture = broker(assessment("Unrelated"))
    drop_shell(server)
    for _ in range(9):
        server.report()
    work(server, fixture)
    (change,) = changes(server)
    assert [len(jobs(server, kind)) for kind in ("server_triage", "server_analysis")] == [1, 1]
    triaged, analysed = [call for call in fixture.calls if call["kind"] == "agent"]
    assert (triaged["profile"]["operation"], triaged["files"], triaged["policy"]) == ("commit_triage", {}, None)
    facts = json.loads(triaged["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert facts["agent"] == "web-1" and facts["diff_complete"] is True and facts["incomplete"] == []
    assert facts["server_change"]["added"][0]["path"] == SHELL_PATH and "+<?php /* stand-in" in facts["diff"]
    # Analysis reads only stored bytes, staged by SHA-256; only server-files.json names server paths.
    assert (analysed["profile"]["operation"], analysed["policy"]) == ("commit_analysis", None)
    listing = json.loads(analysed["files"].pop("server-files.json"))
    assert analysed["files"] == {f"source/changed/{sha(SHELL)}": SHELL}
    assert listing["files"] == {f"source/changed/{sha(SHELL)}": {"root": ROOT, "path": SHELL_PATH,
                                                                 "sha256": sha(SHELL), "held": True}}
    assert analysed["schema"]["properties"]["verdict"]["enum"] == [
        "Malicious change", "Security hardening", "Unrelated", "Insufficient context"]
    assert (change.triage_status, change.verdict, change.review_decision) == ("completed", "Unrelated", "dismissed")
    with server.stand.factory() as db:
        (analysis,) = db.scalars(select(Analysis).where(Analysis.subject_id == change.id))
        assert analysis.kind == "server_analysis"
    (job,) = jobs(server, "server_analysis")
    subject = server.stand.client.get(f"/api/jobs/{job.id}").json()["subject"]
    assert subject == {"type": "server", "label": "web-1 · Server change", "ref": change.fingerprint[:12],
                       "link": f"/applications/{server.stand.application_id}?tab=server"}
    row = shown(server.stand)
    assert row["accept_allowed"] is True
    assert accept(server).status_code == 200
    server.report()
    assert len(changes(server)) == 1


def test_bytes_that_do_not_hash_to_their_sha256_are_refused_by_application_code(server, monkeypatch):
    """AC-B05: the listener refuses them, and application code hashes them again before it holds them."""
    monkeypatch.setattr(ingress, "route_refusal", lambda route, document: None)  # a listener that missed it
    server.files[SHELL_PATH] = server.file(SHELL_PATH, SHELL)
    wanted = server.report(upload=False)
    assert sha(SHELL) in wanted["sha256"]
    forged = {"report_sequence": server.sequence, "complete": True,
              "files": [{"sha256": sha(SHELL), "content_b64": base64.b64encode(b"<?php other ?>").decode()}]}
    assert server.stand.agent.send("POST", "/agent/v1/upload", forged)[0] == 202
    process(server.stand)
    assert {"status": "refused", "reason": "hash_mismatch"} in outcomes(server.stand)
    with server.stand.factory() as db:
        assert db.scalar(select(func.count()).select_from(Artifact).where(Artifact.resource_id == sha(SHELL))) == 0
    assert latest(server)["status"] == "awaiting_uploads"


def test_secret_files_are_never_wanted_and_an_incomplete_change_is_never_unrelated(server):
    """AC-B05 and AC-B06: wp-config.php and .env are reported by hash only, a change to them is
    incomplete, and an incomplete change's Unrelated Verdict is stored as Insufficient context."""
    baselined(server)
    triage(server, "pi")
    server.files["wp-config.php"] = server.file("wp-config.php", b"<?php define('DB_PASSWORD', 'y');\n", secret=True)
    server.files[".env"] = server.file(".env", b"APP_KEY=z\n")  # the dashboard's own list marks it too
    assert server.report() is None  # nothing it may ask for
    work(server, broker(assessment("Unrelated"), triage={"decision": "unrelated", "title": "Config", "reason": "Config"}))
    (change,) = changes(server)
    assert sorted((item["reason"], item["path"]) for item in change.incomplete) == [
        ("secret", ".env"), ("secret", "wp-config.php")]
    # Triage could not confirm unrelated on an incomplete change, and Analysis's Unrelated does not stand.
    assert change.triage_result["decision"] == "insufficient_context"
    assert (change.verdict, change.review_decision) == ("Insufficient context", "pending")
    queue = server.stand.client.get("/api/dashboard").json()["review_queue"]
    assert queue == [{"id": change.id, "title": "web-1 · Server change", "revision": change.fingerprint[:12],
                      "application_id": server.stand.application_id, "committed_at": queue[0]["committed_at"],
                      "link": f"/applications/{server.stand.application_id}?tab=server"}]
    assert accept(server).json()["code"] == "baseline_not_allowed"
    # Decision 14: dismissed from the Review queue, its manifest may become the Baseline.
    reviewed = server.stand.client.post(f"/api/server-changes/{change.id}/review", json={"decision": "dismissed"})
    assert reviewed.status_code == 200 and reviewed.json()["review_decision"] == "dismissed"
    assert server.stand.client.get("/api/dashboard").json()["review_queue"] == []
    assert accept(server).status_code == 200


@pytest.mark.parametrize("verdict", ["Security hardening", "Unrelated"])
def test_security_hardening_and_unrelated_allow_the_later_manifest_as_baseline(server, verdict):
    baselined(server)
    triage(server, "pi")
    drop_shell(server)
    work(server, broker(assessment(verdict)))
    (change,) = changes(server)
    assert change.verdict == verdict
    assert shown(server.stand)["accept_allowed"] is True
    accepted = accept(server)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["baseline"]["manifest_id"] == latest(server)["id"]
    with server.stand.factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0


def test_a_server_file_analysis_that_returns_vulnerability_fix_fails(server):
    """AC-B06: a server-file Analysis that returns Vulnerability fix is rejected as failed."""
    baselined(server)
    triage(server, "pi")
    drop_shell(server)
    work(server, broker({**assessment("Unrelated"), "verdict": "Vulnerability fix"}))
    (job,) = jobs(server, "server_analysis")
    assert (job.status, job.error["code"]) == ("failed", "verdict_not_allowed")
    (change,) = changes(server)
    assert (change.analysis_state["status"], change.verdict) == ("failed", None)
    with server.stand.factory() as db:
        assert db.scalar(select(func.count()).select_from(Analysis)) == 0
    assert accept(server).json()["code"] == "baseline_not_allowed"
    retried = server.stand.client.post(f"/api/jobs/{job.id}/retry")
    assert retried.status_code == 202, retried.text
    with server.stand.factory() as db:
        assert db.get(ServerChange, change.id).analysis_state == {"status": "queued", "job_id": retried.json()["job_id"]}


def test_a_malicious_change_opens_one_server_files_finding_named_by_path_and_sha256(server):
    """B07: a Malicious change opens a server_files Finding whose one Alert's source is the agent's
    name, never a path; it names the dropped file by path and SHA-256, offers no Lab and no
    Remediation PR, and its manifest can never become the Baseline."""
    baselined(server)
    triage(server, "pi")
    drop_shell(server)
    client = server.stand.client
    work(server, broker(assessment("Malicious change", [f"{ROOT}/{SHELL_PATH}", "index.php", "nowhere.php"])))
    (change,) = changes(server)
    (listed,) = client.get("/api/findings").json()["items"]
    finding = client.get(f"/api/findings/{listed['id']}").json()
    assert (finding["source"], finding["source_ref"], finding["subject_id"], finding["agent_id"]) == (
        "server_files", "web-1", change.id, server.stand.agent.agent_id)
    assert finding["server_files"] == [{"root": ROOT, "path": SHELL_PATH, "sha256": sha(SHELL)}]
    assert finding["server_indicators"]["rejected"] == [
        {"kind": "file", "value": "index.php", "reason": "Not an added or changed file of this Server change"},
        {"kind": "file", "value": "nowhere.php", "reason": "Not an added or changed file of this Server change"}]
    assert [(row["step"], row["status"]) for row in finding["playbook"]] == [("quarantine", "waiting_for_approval")]
    assert shown(server.stand)["changes"][0]["finding_id"] == finding["id"]
    with server.stand.factory() as db:
        (alert,) = db.scalars(select(Notification))
    assert alert.data == {"application": alert.data["application"], "account": None, "source": "web-1",
                          "verdict": "Malicious change · high confidence", "link": f"/findings/{finding['id']}"}
    assert SHELL_PATH not in json.dumps(alert.data) and "cache.php" not in json.dumps(alert.data)
    assert finding["remediation_actions"] == []
    lab = client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL)
    assert (lab.status_code, lab.json()["code"]) == (409, "lab_not_allowed")
    assert accept(server).json()["code"] == "baseline_not_allowed"
    assert client.post(f"/api/server-changes/{change.id}/review", json={"decision": "dismissed"}).status_code == 200
    assert accept(server).json()["code"] == "baseline_not_allowed"
    # A repeat Analysis never opens a second Finding or a second Alert.
    assert client.post(f"/api/server-changes/{change.id}/analyses", json={}).status_code == 202
    work(server, broker(assessment("Malicious change", [SHELL_PATH])))
    with server.stand.factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 1
        assert db.scalar(select(func.count()).select_from(Notification)) == 1
